use once_cell::sync::Lazy;
use std::io;
use std::mem;
use std::net::SocketAddr;
use std::os::windows::io::{AsRawSocket, RawSocket};
use std::ptr;
use tokio::net::{ToSocketAddrs, UdpSocket, lookup_host};
use windows_sys::core::GUID;
use windows_sys::Win32::Networking::WinSock::{
    closesocket, setsockopt, socket, WSAIoctl, AF_INET, AF_INET6, IN6_PKTINFO, INVALID_SOCKET,
    IN_PKTINFO, IPPROTO_IP, IPPROTO_IPV6, IPPROTO_UDP, IPV6_ECN, IPV6_PKTINFO, IP_ECN, IP_PKTINFO,
    LPFN_WSARECVMSG, LPFN_WSASENDMSG, LPWSAOVERLAPPED_COMPLETION_ROUTINE,
    SIO_GET_EXTENSION_FUNCTION_POINTER, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET, SOCKET,
    SOCK_DGRAM, UDP_RECV_MAX_COALESCED_SIZE, WSABUF, WSAMSG,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

pub async fn bind_sas<A: ToSocketAddrs>(addr: A) -> io::Result<UdpSocket> {
    let mut addrs = lookup_host(addr).await?;
    let local = match addrs.next() {
        Some(local) => local,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no addresses to bind",
            ));
        }
    };
    let socket = if local.is_ipv4() {
        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?
    } else {
        let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?;
        socket.set_only_v6(true).unwrap();
        socket
    };

    let address = local.into();
    socket.bind(&address)?;
    socket.set_nonblocking(true).unwrap();

    let (level, optname) = if local.is_ipv4() {
        (IPPROTO_IP as i32, IP_PKTINFO as i32)
    } else {
        (IPPROTO_IPV6 as i32, IPV6_PKTINFO as i32)
    };
    let optval = [1u32; 1];
    let res = unsafe {
        setsockopt(
            socket.as_raw_socket() as _,
            level as _,
            optname as _,
            optval.as_ptr() as _,
            mem::size_of_val(&optval) as _,
        )
    };
    if res != 0 {
        return Err(io::Error::last_os_error());
    }

    let (level, optname) = if local.is_ipv4() {
        (IPPROTO_IP as i32, IP_ECN as i32)
    } else {
        (IPPROTO_IPV6 as i32, IPV6_ECN as i32)
    };
    let optval = [1u32; 1];
    let res = unsafe {
        setsockopt(
            socket.as_raw_socket() as _,
            level as _,
            optname as _,
            optval.as_ptr() as _,
            mem::size_of_val(&optval) as _,
        )
    };
    if res != 0 {
        return Err(io::Error::last_os_error());
    }

    let optval = [65536u32 - 8u32; 1];
    let res = unsafe {
        setsockopt(
            socket.as_raw_socket() as _,
            IPPROTO_UDP as _,
            UDP_RECV_MAX_COALESCED_SIZE as _,
            optval.as_ptr() as _,
            mem::size_of_val(&optval) as _,
        )
    };
    if res != 0 {
        return Err(io::Error::last_os_error());
    }

    let socket: std::net::UdpSocket = socket.into();
    Ok(tokio::net::UdpSocket::from_std(socket).unwrap())
}

pub fn try_recv_sas(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, Option<SocketAddr>, Option<SocketAddr>)> {
    let wsarecvmsg = if let Some(extension) = *WSARECVMSG {
        extension
    } else {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "WSARecvMsg extension not foud",
        ));
    };

    socket.try_io(tokio::io::Interest::READABLE, || {
        let mut control_buffer = [0; 128];
        let mut source: SOCKADDR_INET = unsafe { mem::zeroed() };

        let mut data = WSABUF {
            buf: buf.as_mut_ptr(),
            len: buf.len() as _,
        };

        let control = WSABUF {
            buf: control_buffer.as_mut_ptr(),
            len: control_buffer.len() as _,
        };

        let mut wsa_msg = WSAMSG {
            name: &mut source as *mut _ as *mut _,
            namelen: mem::size_of_val(&source) as _,
            lpBuffers: &mut data,
            Control: control,
            dwBufferCount: 1,
            dwFlags: 0,
        };

        let mut read_bytes = 0;

        let res = {
            unsafe {
                (wsarecvmsg)(
                    socket.as_raw_socket() as _,
                    &mut wsa_msg,
                    &mut read_bytes,
                    ptr::null_mut(),
                    None,
                )
            }
        };
        if res == 0 {
            let mut destination_address = None;
            unsafe {
                let mut cmsg = wsa_cmsg_firsthdr(&wsa_msg);
                while cmsg != ptr::null_mut() {
                    if (*cmsg).cmsg_level == IPPROTO_IP as i32
                        && (*cmsg).cmsg_type == IP_PKTINFO as i32
                        && (*cmsg).cmsg_len >= wsa_cmsg_len(mem::size_of::<IN_PKTINFO>())
                    {
                        let info: IN_PKTINFO = ptr::read(wsa_cmsg_data(cmsg) as *const _);
                        let destination = SOCKADDR_IN {
                            sin_family: AF_INET as _,
                            sin_addr: info.ipi_addr,
                            sin_port: 0,
                            sin_zero: [0u8; 8],
                        };
                        let (_, address) = socket2::SockAddr::try_init(|addr_storage, len| {
                            *len = mem::size_of_val(&destination) as _;
                            std::ptr::copy_nonoverlapping(&destination, addr_storage as _, 1);
                            Ok(())
                        })?;
                        destination_address = address.as_socket()
                    }
                    if (*cmsg).cmsg_level == IPPROTO_IPV6 as i32
                        && (*cmsg).cmsg_type == IPV6_PKTINFO as i32
                        && (*cmsg).cmsg_len >= wsa_cmsg_len(mem::size_of::<IN6_PKTINFO>())
                    {
                        let info: IN6_PKTINFO = ptr::read(wsa_cmsg_data(cmsg) as *const _);
                        let mut destination: SOCKADDR_IN6 = mem::zeroed();
                        destination.sin6_family = AF_INET6 as _;
                        destination.sin6_addr = info.ipi6_addr;
                        let (_, address) = socket2::SockAddr::try_init(|addr_storage, len| {
                            *len = mem::size_of_val(&destination) as _;
                            std::ptr::copy_nonoverlapping(&destination, addr_storage as _, 1);
                            Ok(())
                        })?;
                        destination_address = address.as_socket()
                    }
                    cmsg = wsa_cmsg_nxthdr(&wsa_msg, cmsg);
                }
            }
            let source_address = unsafe {
                let (_, address) = socket2::SockAddr::try_init(|addr_storage, len| {
                    *len = mem::size_of_val(&source) as _;
                    ptr::copy_nonoverlapping(&source, addr_storage as _, 1);
                    Ok(())
                })?;
                address.as_socket()
            };
            Ok((read_bytes as usize, source_address, destination_address))
        } else {
            Err(std::io::Error::last_os_error())
        }
    })
}

pub fn try_send_sas(
    socket: &UdpSocket,
    buf: &[u8],
    remote: SocketAddr,
    local: SocketAddr,
) -> io::Result<usize> {
    let wsasendmsg = if let Some(extension) = *WSASENDMSG {
        extension
    } else {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "WSASendMsg extension not foud",
        ));
    };
    let remote = socket2::SockAddr::from(remote);
    let local = socket2::SockAddr::from(local);

    let mut control_buffer = [0; 128];

    let mut wsa_msg = WSAMSG {
        name: remote.as_ptr() as *mut _,
        namelen: remote.len(),
        lpBuffers: &mut WSABUF { len: buf.len() as _, buf: buf.as_ptr() as *mut _},
        Control: WSABUF { len: 0, buf: control_buffer.as_mut_ptr() },
        dwBufferCount: 1,
        dwFlags: 0,
    };

    match local.family() {
        AF_INET => {
            let local: SOCKADDR_IN = unsafe { ptr::read(local.as_ptr() as _) };
            let info = IN_PKTINFO {
                ipi_addr: local.sin_addr,
                ipi_ifindex: 0,
            };

            wsa_msg.Control.len += wsa_cmsg_space(mem::size_of::<IN_PKTINFO>()) as u32;
            unsafe {
                let mut cmsg = wsa_cmsg_firsthdr(&wsa_msg);
                (*cmsg).cmsg_level = IPPROTO_IP as _;
                (*cmsg).cmsg_type = IP_PKTINFO as _;
                (*cmsg).cmsg_len = wsa_cmsg_len(mem::size_of::<IN_PKTINFO>());
                ptr::copy(
                    &info as *const _ as *const _,
                    wsa_cmsg_data(cmsg),
                    mem::size_of::<IN_PKTINFO>(),
                );
            }
        },
        AF_INET6 => {
            let local: SOCKADDR_IN6 = unsafe { ptr::read(local.as_ptr() as _) };
            let info = IN6_PKTINFO {
                ipi6_addr: local.sin6_addr,
                ipi6_ifindex: unsafe {local.Anonymous.sin6_scope_id},
            };

            wsa_msg.Control.len += wsa_cmsg_space(mem::size_of::<IN6_PKTINFO>()) as u32;
            unsafe {
                let mut cmsg = wsa_cmsg_firsthdr(&wsa_msg);
                (*cmsg).cmsg_level = IPPROTO_IPV6 as _;
                (*cmsg).cmsg_type = IPV6_PKTINFO as _;
                (*cmsg).cmsg_len = wsa_cmsg_len(mem::size_of::<IN6_PKTINFO>());
                ptr::copy(
                    &info as *const _ as *const _,
                    wsa_cmsg_data(cmsg),
                    mem::size_of::<IN6_PKTINFO>(),
                );
                
            }
        },
        _ => {
            return Err(io::Error::new(io::ErrorKind::Other, "not an inet addr"));
        }
    };

    socket.try_io(tokio::io::Interest::WRITABLE, || {
        let mut sent_bytes = 0;
        let res = unsafe {
            (wsasendmsg)(
                socket.as_raw_socket() as _,
                &mut wsa_msg,
                0,
                &mut sent_bytes,
                ptr::null_mut(),
                None,
            )
        };

        if res == 0 {
            Ok(sent_bytes as usize)
        } else {
            Err(std::io::Error::last_os_error())
        }
    })
}

#[repr(C)]
struct WSACMSGHDR {
    cmsg_len: usize,
    cmsg_level: i32,
    cmsg_type: i32,
}

fn wsa_cmsghdr_align(length: usize) -> usize {
    length + mem::align_of::<WSACMSGHDR>() - 1 & !(mem::align_of::<WSACMSGHDR>() - 1)
}

fn wsa_cmsgdata_align(length: usize) -> usize {
    length + mem::align_of::<usize>() - 1 & !(mem::align_of::<usize>() - 1)
}

unsafe fn wsa_cmsg_firsthdr(msg: *const WSAMSG) -> *mut WSACMSGHDR {
    if (*msg).Control.len as usize >= mem::size_of::<WSACMSGHDR>() {
        (*msg).Control.buf as *mut WSACMSGHDR
    } else {
        0 as *mut WSACMSGHDR
    }
}

unsafe fn wsa_cmsg_nxthdr(msg: *const WSAMSG, cmsg: *const WSACMSGHDR) -> *mut WSACMSGHDR {
    if cmsg == ptr::null() {
        return wsa_cmsg_firsthdr(msg);
    }
    let next = (cmsg as usize + wsa_cmsghdr_align((*cmsg).cmsg_len as usize)) as *mut WSACMSGHDR;
    let max = (*msg).Control.buf as usize + (*msg).Control.len as usize;
    if (next.offset(1)) as usize > max {
        ptr::null_mut()
    } else {
        next as *mut WSACMSGHDR
    }
}

unsafe fn wsa_cmsg_data(cmsg: *const WSACMSGHDR) -> *mut u8 {
    cmsg.offset(1) as *mut u8
}

#[inline]
fn wsa_cmsg_space(length: usize) -> usize {
    wsa_cmsgdata_align(mem::size_of::<WSACMSGHDR>() + wsa_cmsghdr_align(length))
}

fn wsa_cmsg_len(length: usize) -> usize {
    wsa_cmsgdata_align(mem::size_of::<WSACMSGHDR>()) + length
}

static WSARECVMSG: Lazy<Option<WSARecvMsg>> = Lazy::new(|| unsafe {
    let s = socket(AF_INET as _, SOCK_DGRAM as _, 0);
    if s == INVALID_SOCKET {
        return None;
    }
    let res = locate_wsarecvmsg(s as RawSocket);
    closesocket(s);
    if let Ok(extension) = res {
        Some(extension)
    } else {
        None
    }
});

static WSASENDMSG: Lazy<Option<WSASendMsg>> = Lazy::new(|| unsafe {
    let s = socket(AF_INET as _, SOCK_DGRAM as _, 0);
    if s == INVALID_SOCKET {
        return None;
    }
    let res = locate_wsasendmsg(s as RawSocket);
    closesocket(s);
    if let Ok(extension) = res {
        Some(extension)
    } else {
        None
    }
});

const WSAID_WSARECVMSG: GUID = GUID {
    data1: 0xf689d7c8,
    data2: 0x6f1f,
    data3: 0x436b,
    data4: [0x8a, 0x53, 0xe5, 0x4f, 0xe3, 0x51, 0xc3, 0x22],
};

type WSARecvMsg = unsafe extern "system" fn(
    s: SOCKET,
    lpMsg: *mut WSAMSG,
    lpdwnumberofbytesrecvd: *mut u32,
    lpoverlapped: *mut OVERLAPPED,
    lpcompletionroutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32;

fn locate_wsarecvmsg(socket: RawSocket) -> io::Result<WSARecvMsg> {
    let mut func: LPFN_WSARECVMSG = None;
    let mut byte_len: u32 = 0;

    let res = unsafe {
        WSAIoctl(
            socket as _,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &WSAID_WSARECVMSG as *const _ as *mut _,
            mem::size_of_val(&WSAID_WSARECVMSG) as _,
            &mut func as *const _ as *mut _,
            mem::size_of_val(&func) as _,
            &mut byte_len,
            ptr::null_mut(),
            None,
        )
    };
    if res != 0 {
        return Err(io::Error::last_os_error());
    }

    if byte_len as usize != mem::size_of::<LPFN_WSARECVMSG>() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Locating fn pointer to WSARecvMsg returned different expected bytes",
        ));
    }
    match func {
        None => Err(io::Error::new(
            io::ErrorKind::Other,
            "WSARecvMsg extension not foud",
        )),
        Some(extension) => Ok(extension),
    }
}

const WSAID_WSASENDMSG: GUID = GUID {
    data1: 0xa441e712,
    data2: 0x754f,
    data3: 0x43ca,
    data4: [0x84, 0xa7, 0x0d, 0xee, 0x44, 0xcf, 0x60, 0x6d],
};

pub type WSASendMsg = unsafe extern "system" fn(
    s: SOCKET,
    lpMsg: *const WSAMSG,
    dwFlags: u32,
    lpNumberOfBytesSent: *mut u32,
    lpOverlapped: *mut OVERLAPPED,
    lpCompletionRoutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32;

pub fn locate_wsasendmsg(socket: RawSocket) -> io::Result<WSASendMsg> {
    let mut func: LPFN_WSASENDMSG = None;
    let mut byte_len: u32 = 0;

    let r = unsafe {
        WSAIoctl(
            socket as _,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &WSAID_WSASENDMSG as *const _ as *mut _,
            mem::size_of_val(&WSAID_WSASENDMSG) as _,
            &mut func as *const _ as *mut _,
            mem::size_of_val(&func) as _,
            &mut byte_len,
            ptr::null_mut(),
            None,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }

    if byte_len as usize != mem::size_of::<LPFN_WSASENDMSG>() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Locating fn pointer to WSASendMsg returned different expected bytes",
        ));
    }

    match func {
        None => Err(io::Error::new(
            io::ErrorKind::Other,
            "WSASendMsg extension not foud",
        )),
        Some(extension) => Ok(extension),
    }
}

#[cfg(test)]
mod tests {
    use crate::sas::{recv_sas, send_sas};
    use super::*;

    #[tokio::test]
    async fn test_recv_sas_ipv4() {
        let receiver = bind_sas("0.0.0.0:3456").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:4567").await.unwrap();
        let send_buf = b"hello";
        let mut recv_buf = vec![0u8; 1500];

        sender.send_to(send_buf, "127.0.0.1:3456").await.unwrap();
        sender.send_to(send_buf, "127.0.0.2:3456").await.unwrap();

        if let Ok((n, from, to)) = recv_sas(&receiver, &mut recv_buf).await {
            assert_eq!(n, 5);
            assert_eq!(from, Some("127.0.0.1:4567".parse().unwrap()));
            assert_eq!(to, Some("127.0.0.1:0".parse().unwrap()));
        }

        if let Ok((n, from, to)) = recv_sas(&receiver, &mut recv_buf).await {
            assert_eq!(n, 5);
            assert_eq!(from, Some("127.0.0.1:4567".parse().unwrap()));
            assert_eq!(to, Some("127.0.0.2:0".parse().unwrap()));
        }
    }

    #[tokio::test]
    async fn test_recv_sas_ipv6() {
        let receiver = bind_sas("[::]:3456").await.unwrap();
        let sender = UdpSocket::bind("[::1]:4567").await.unwrap();
        let send_buf = b"hello";
        let mut recv_buf = vec![0u8; 1500];

        sender.send_to(send_buf, "[::1]:3456").await.unwrap();

        if let Ok((n, from, to)) = recv_sas(&receiver, &mut recv_buf).await {
            assert_eq!(n, 5);
            assert_eq!(from, Some("[::1]:4567".parse().unwrap()));
            assert_eq!(to, Some("[::1]:0".parse().unwrap()));
        }
    }

    #[tokio::test]
    async fn test_send_sas_ipv4() {
        use tokio_stream::StreamExt;
        use if_watch::tokio::IfWatcher;
        use std::net::IpAddr;

        let sender = bind_sas("0.0.0.0:0").await.unwrap();
        let send_buf = b"hello";

        let mut ifwatcher = IfWatcher::new().unwrap();
        ifwatcher.next().await;
        for ipnet in ifwatcher.iter() {
            match ipnet.addr() {
                IpAddr::V4(addr) => {
                    let local = SocketAddr::new(IpAddr::V4(addr), 0);
                    match send_sas(&sender, send_buf, "192.0.2.1:3456", local).await {
                        Ok(n) => {
                            eprintln!("Succeed in sending from {}", local);
                            assert_eq!(n, 5);
                        }
                        Err(_) => {
                            eprintln!("Failed to send from {}", local);
                        }
                    }
                }
                IpAddr::V6(_) => {}
            }
        }
    }

    #[tokio::test]
    async fn test_send_sas_ipv6() {
        use tokio_stream::StreamExt;
        use if_watch::tokio::IfWatcher;
        use std::net::IpAddr;

        let sender = bind_sas("[::]:0").await.unwrap();
        let send_buf = b"hello";

        let mut ifwatcher = IfWatcher::new().unwrap();
        ifwatcher.next().await;
        for ipnet in ifwatcher.iter() {
            match ipnet.addr() {
                IpAddr::V4(_) => {}
                IpAddr::V6(addr) => {
                    let local = SocketAddr::new(IpAddr::V6(addr), 0);
                    match send_sas(&sender, send_buf, "[2001:0db8:0a0b:12f0::1]:3456", local).await {
                        Ok(n) => {
                            eprintln!("Succeed in sending from {}", local);
                            assert_eq!(n, 5);
                        }
                        Err(e) => {
                            eprintln!("Failed to send from {}, {:?}", local, e);
                        }
                    }
                }
            }
        }
    }
}
