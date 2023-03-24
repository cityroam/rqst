use bytes::{Bytes, BytesMut};
use std::collections::{btree_map, BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::{Stream, StreamExt, StreamMap};

use ring::rand::*;
use std::net::SocketAddr;

use crate::sas::{bind_sas, select_local_ipaddr, send_sas, try_recv_sas};

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

type SocketHandle = usize;
type SocketMap = HashMap<SocketHandle, Arc<UdpSocket>>;
type ConnectionHandle = u64;

struct QuicActor {
    receiver: mpsc::Receiver<ActorMessage>,
    next_socket_handle: SocketHandle,
    sockets: SocketMap,
    addrs_to_sockets: HashMap<SocketAddr, SocketHandle>,
    recv_stream:
        StreamMap<usize, Pin<Box<dyn Stream<Item = (BytesMut, SocketAddr, SocketAddr)> + Send>>>,
    config: quiche::Config,
    keylog: Option<File>,
    conn_id_len: usize,
    client_cert_required: bool,
    next_conn_handle: ConnectionHandle,
    conn_ids: QuicConnectionIdMap,
    conns: QuicConnectionMap,
    wait_conn_handles: VecDeque<ConnectionHandle>,
    accept_requests: VecDeque<AcceptRequest>,
    shutdown: bool,
    out: Vec<u8>,
    _shutdown_complete: mpsc::Sender<()>,
}

#[derive(Debug)]
enum ActorMessage {
    Accept {
        respond_to: oneshot::Sender<Result<ConnectionHandle>>,
    },
    Listen {
        local: SocketAddr,
        respond_to: oneshot::Sender<Result<()>>,
    },
    Connect {
        url: url::Url,
        local_addr: Option<SocketAddr>,
        respond_to: oneshot::Sender<Result<ConnectionHandle>>,
    },
    WaitConnected {
        conn_handle: ConnectionHandle,
        respond_to: oneshot::Sender<Result<()>>,
    },
    RecvStreamReadness {
        conn_handle: ConnectionHandle,
        stream_ids: Option<Vec<u64>>,
        filter: Option<(bool, bool, bool, bool)>,
        respond_to: oneshot::Sender<Result<Vec<u64>>>,
    },
    RecvStream {
        conn_handle: ConnectionHandle,
        stream_id: u64,
        respond_to: oneshot::Sender<Result<Option<(Bytes, bool)>>>,
    },
    RecvDgramReadness {
        conn_handle: ConnectionHandle,
        respond_to: oneshot::Sender<Result<()>>,
    },
    RecvDgram {
        conn_handle: ConnectionHandle,
        respond_to: oneshot::Sender<Result<Option<Bytes>>>,
    },
    RecvDgramVectored {
        conn_handle: ConnectionHandle,
        max_len: usize,
        respond_to: oneshot::Sender<Result<Vec<Bytes>>>,
    },
    RecvDgramInfo {
        conn_handle: ConnectionHandle,
        respond_to: oneshot::Sender<Result<(Option<usize>, usize, usize)>>,
    },
    SendStream {
        conn_handle: ConnectionHandle,
        buf: Bytes,
        stream_id: u64,
        fin: bool,
        respond_to: oneshot::Sender<Result<()>>,
    },
    SetStreamGroup {
        conn_handle: ConnectionHandle,
        stream_id: u64,
        group_id: u64,
        respond_to: oneshot::Sender<Result<()>>,
    },
    SendDgram {
        conn_handle: ConnectionHandle,
        buf: Bytes,
        group_id: u64,
        respond_to: oneshot::Sender<Result<()>>,
    },
    Stats {
        conn_handle: ConnectionHandle,
        respond_to: oneshot::Sender<Result<quiche::Stats>>,
    },
    Close {
        conn_handle: ConnectionHandle,
        respond_to: oneshot::Sender<Result<()>>,
    },
    PathStats {
        conn_handle: ConnectionHandle,
        respond_to: oneshot::Sender<Result<Vec<quiche::PathStats>>>,
    },
    ProbePath {
        conn_handle: ConnectionHandle,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        respond_to: oneshot::Sender<Result<SocketAddr>>,
    },
    PathEventReadness {
        conn_handle: ConnectionHandle,
        respond_to: oneshot::Sender<Result<()>>,
    },
    PathEvent {
        conn_handle: ConnectionHandle,
        respond_to: oneshot::Sender<Result<Option<quiche::PathEvent>>>,
    },
    InsertGroup {
        conn_handle: ConnectionHandle,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        group_id: u64,
        respond_to: oneshot::Sender<Result<bool>>,
    },
    SetActive {
        conn_handle: ConnectionHandle,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        is_active: bool,
        respond_to: oneshot::Sender<Result<()>>,
    },
}

struct QuicConnection {
    quiche_conn: quiche::Connection,
    locals_to_sockets: HashMap<SocketAddr, Arc<UdpSocket>>,
    before_established: bool,
    wait_connected_request: Option<VecDeque<WaitConnectedRequest>>,
    recv_stream_readness_requests: VecDeque<RecvStreamReadnessRequest>,
    send_stream_requests: BTreeMap<u64, VecDeque<SendStreamRequest>>,
    recv_dgram_readness_requests: VecDeque<RecvDgramReadnessRequest>,
    send_dgram_requests: VecDeque<SendDgramRequest>,
    probe_path_requests: VecDeque<ProbePathRequest>,
    path_events: VecDeque<quiche::PathEvent>,
    path_event_readness_requests: VecDeque<PathEventReadnessRequest>,
}
type QuicConnectionIdMap = HashMap<quiche::ConnectionId<'static>, ConnectionHandle>;
type QuicConnectionMap = HashMap<ConnectionHandle, QuicConnection>;

struct AcceptRequest {
    respond_to: oneshot::Sender<Result<ConnectionHandle>>,
}

struct WaitConnectedRequest {
    respond_to: oneshot::Sender<Result<()>>,
}

struct RecvDgramReadnessRequest {
    respond_to: oneshot::Sender<Result<()>>,
}

struct SendDgramRequest {
    buf: Bytes,
    group_id: u64,
    respond_to: oneshot::Sender<Result<()>>,
}

struct RecvStreamReadnessRequest {
    stream_ids: Option<Vec<u64>>,
    filter: Option<(bool, bool, bool, bool)>,
    respond_to: Option<oneshot::Sender<Result<Vec<u64>>>>,
}

struct SendStreamRequest {
    buf: Bytes,
    fin: bool,
    respond_to: oneshot::Sender<Result<()>>,
}

struct ProbePathRequest {
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

struct PathEventReadnessRequest {
    respond_to: oneshot::Sender<Result<()>>,
}

impl QuicActor {
    fn new(
        receiver: mpsc::Receiver<ActorMessage>,
        config: quiche::Config,
        keylog: Option<File>,
        conn_id_len: usize,
        client_cert_required: bool,
        shutdown_complete: mpsc::Sender<()>,
    ) -> Self {
        QuicActor {
            receiver,
            next_socket_handle: 0,
            sockets: SocketMap::new(),
            addrs_to_sockets: HashMap::new(),
            recv_stream: StreamMap::new(),
            config,
            keylog,
            conn_id_len,
            client_cert_required,
            next_conn_handle: 0,
            conn_ids: QuicConnectionIdMap::new(),
            conns: QuicConnectionMap::new(),
            wait_conn_handles: VecDeque::new(),
            accept_requests: VecDeque::new(),
            shutdown: false,
            out: vec![0; 1350],
            _shutdown_complete: shutdown_complete,
        }
    }

    async fn add_socket(&mut self, local: SocketAddr) -> std::io::Result<(SocketHandle, SocketAddr)> {
        if local.port() != 0 && self.addrs_to_sockets.contains_key(&local) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "Already added",
            ));
        }
        let socket = bind_sas(&local).await?;
        let binded_local = socket.local_addr().expect("no local address");
        let socket: socket2::Socket = socket.into_std()?.into();
        socket.set_recv_buffer_size(0x7fffffff)?;
        let socket: std::net::UdpSocket = socket.into();
        let socket = Arc::new(tokio::net::UdpSocket::from_std(socket)?);

        let socket_handle = self.next_socket_handle;
        self.sockets.insert(socket_handle, socket.clone());
        self.addrs_to_sockets.insert(binded_local, socket_handle);
        self.next_socket_handle += 1;

        let stream = Box::pin(async_stream::stream! {
            'outer: loop {
                if socket.readable().await.is_ok() {
                    'inner: loop {
                        let mut buf = BytesMut::with_capacity(2048);
                        buf.resize(2048, 0);
                        match try_recv_sas(&socket, &mut buf[..]) {
                            Ok((len, from, to)) => {
                                buf.truncate(len);
                                let from = from.unwrap();
                                let to = if to.is_some() {
                                    let mut to = to.unwrap();
                                    to.set_port(binded_local.port());
                                    to
                                } else {
                                    local
                                };
                                yield((buf, from, to));
                            },
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                break 'inner;
                            },
                            Err(e) => {
                                error!("try_recv_from() failed: {:?}", e);
                                break 'outer;
                            }
                        }
                    }
                }
            }
        })
            as Pin<Box<dyn Stream<Item = (BytesMut, SocketAddr, SocketAddr)> + Send>>;
        self.recv_stream.insert(socket_handle, stream);
        Ok((socket_handle, binded_local))
    }

    async fn handle_message(&mut self, msg: ActorMessage) {
        match msg {
            ActorMessage::Accept { respond_to } => {
                if let Some(conn_handle) = self.wait_conn_handles.pop_front() {
                    if let Err(Ok(conn_handle)) = respond_to.send(Ok(conn_handle)) {
                        self.wait_conn_handles.push_front(conn_handle);
                    }
                } else {
                    self.accept_requests.push_back(AcceptRequest { respond_to });
                }
            }
            ActorMessage::Listen { local, respond_to } => match self.add_socket(local).await {
                Ok(_) => {
                    let _ = respond_to.send(Ok(()));
                }
                Err(e) => {
                    let _ = respond_to.send(Err(format!("add_socket failed: {:?}", e).into()));
                }
            },
            ActorMessage::Connect {
                url,
                local_addr,
                respond_to,
            } => {
                let (to, mut from) = if let Some(local_addr) = local_addr {
                    let to = match url.socket_addrs(|| None) {
                        Ok(addrs) => {
                            let addr = addrs.iter().find(|v|
                                v.is_ipv4() == local_addr.is_ipv4() ||
                                v.is_ipv6() == local_addr.is_ipv6()
                            );
                            if let Some(addr) = addr {
                                addr.clone()
                            } else {
                                let _ = respond_to.send(Err(format!("No address for {:?}", url).into()));
                                return;
                            }
                        }
                        Err(e) => {
                            let _ = respond_to.send(Err(format!("{:?} not resolved: {:?}", url, e).into()));
                            return; 
                        }
                    };
                    (to, local_addr)
                } else {
                    let to = match url.socket_addrs(|| None) {
                        Ok(addrs) => {
                            if let Some(addr) = addrs.iter().next() {
                                addr.clone()
                            } else {
                                let _ = respond_to.send(Err(format!("No address for {:?}", url).into()));
                                return;
                            }
                        }
                        Err(e) => {
                            let _ = respond_to.send(Err(format!("{:?} not resolved: {:?}", url, e).into()));
                            return; 
                        }
                    };
                    let from = SocketAddr::new(
                        select_local_ipaddr(to, None).await.unwrap(),
                        0
                    );
                    (to, from)
                };
                let local = if to.is_ipv4() {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), from.port())
                } else {
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), from.port())
                };

                let (socket_handle, binded_local) = match self.add_socket(local).await {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = respond_to.send(Err(format!("add_socket() failed: {:?}", e).into()));
                        return;
                    }
                };
                if from.port() == 0 {
                    from.set_port(binded_local.port());
                }
                
                // Generate a random source connection ID for the connection.
                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                let scid = &mut scid[0..self.conn_id_len];
                ring::rand::SystemRandom::new().fill(&mut scid[..]).unwrap();

                let scid = quiche::ConnectionId::from_ref(&scid).into_owned();
                // Create a QUIC connection and initiate handshake.
                let mut conn =
                    quiche::connect(url.domain(), &scid, from, to, &mut self.config).unwrap();

                if let Some(keylog) = &self.keylog {
                    if let Ok(keylog) = keylog.try_clone() {
                        conn.set_keylog(Box::new(keylog));
                    }
                }

                if let Some(dir) = std::env::var_os("QLOGDIR") {
                    let writer = make_qlog_writer(&dir, "client", &conn.trace_id());

                    conn.set_qlog(
                        std::boxed::Box::new(writer),
                        "quiche-client qlog".to_string(),
                        format!("{} id={}", "quiche-client qlog", conn.trace_id()),
                    );
                }

                let (write, send_info) = conn.send(&mut self.out).expect("initial send failed");

                let socket = self.sockets.get(&socket_handle).unwrap();
                match send_sas(socket, &self.out[..write], &send_info.to, &send_info.from)
                    .await
                {
                    Ok(_) => {},
                    Err(e) => {
                        error!("send_sas() failed: {:?}", e);
                    }
                }

                let mut locals_to_sockets = HashMap::new();
                locals_to_sockets.insert(send_info.from, socket.clone());

                let conn_handle = self.next_conn_handle;
                self.conns.insert(
                    conn_handle,
                    QuicConnection {
                        quiche_conn: conn,
                        locals_to_sockets,
                        before_established: true,
                        wait_connected_request: Some(VecDeque::new()),
                        recv_stream_readness_requests: VecDeque::new(),
                        send_stream_requests: BTreeMap::new(),
                        recv_dgram_readness_requests: VecDeque::new(),
                        send_dgram_requests: VecDeque::new(),
                        probe_path_requests: VecDeque::new(),
                        path_events: VecDeque::new(),
                        path_event_readness_requests: VecDeque::new(),
                    },
                );
                self.conn_ids.insert(scid, conn_handle);
                self.next_conn_handle = self.next_conn_handle.saturating_add(1);
                respond_to.send(Ok(conn_handle)).ok();
            }
            ActorMessage::WaitConnected {
                conn_handle,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    if conn.wait_connected_request.is_none() {
                        let _ = respond_to.send(Err("connect() not called".into()));
                        return;
                    }
                    if conn.quiche_conn.is_established() {
                        respond_to.send(Ok(())).ok();
                    } else {
                        if let Some(queue) = &mut conn.wait_connected_request {
                            queue.push_back(WaitConnectedRequest { respond_to });
                        }
                    }
                }
            }
            ActorMessage::RecvStreamReadness {
                conn_handle,
                stream_ids,
                filter,
                respond_to,
            } => {
                let filter = filter.unwrap_or((true, true, true, true));
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    let readable = if let Some(stream_ids) = &stream_ids {
                        let stream_ids = stream_ids.iter().cloned().collect::<HashSet<u64>>();
                        let readable = conn.quiche_conn.readable().collect::<HashSet<u64>>();
                        stream_ids
                            .intersection(&readable)
                            .cloned()
                            .filter(|id| match (*id & 0x03, filter) {
                                (0x00, (true, _, _, _))
                                | (0x01, (_, true, _, _))
                                | (0x02, (_, _, true, _))
                                | (0x03, (_, _, _, true)) => true,
                                _ => false,
                            })
                            .collect::<Vec<u64>>()
                    } else {
                        conn.quiche_conn
                            .readable()
                            .filter(|id| match (*id & 0x03, filter) {
                                (0x00, (true, _, _, _))
                                | (0x01, (_, true, _, _))
                                | (0x02, (_, _, true, _))
                                | (0x03, (_, _, _, true)) => true,
                                _ => false,
                            })
                            .collect::<Vec<u64>>()
                    };
                    if !readable.is_empty() {
                        respond_to.send(Ok(readable)).ok();
                    } else {
                        conn.recv_stream_readness_requests
                            .push_back(RecvStreamReadnessRequest {
                                stream_ids,
                                filter: Some(filter),
                                respond_to: Some(respond_to),
                            });
                    }
                } else {
                    respond_to
                        .send(Err(format!("No Connection: {:?}", conn_handle).into()))
                        .ok();
                }
            }
            ActorMessage::RecvStream {
                conn_handle,
                stream_id,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    let mut buf = BytesMut::with_capacity(4096);
                    buf.resize(4096, 0);
                    match conn.quiche_conn.stream_recv(stream_id, &mut buf) {
                        Ok((read, fin)) => {
                            buf.truncate(read);
                            respond_to.send(Ok(Some((buf.freeze(), fin)))).ok();
                        }
                        Err(e) if e == quiche::Error::Done => {
                            respond_to.send(Ok(None)).ok();
                        }
                        Err(e) => {
                            respond_to
                                .send(Err(format!("stream_recv failed: {:?}", e).into()))
                                .ok();
                        }
                    }
                } else {
                    let _ =
                        respond_to.send(Err(format!("No Connection: {:?}", conn_handle).into()));
                }
            }
            ActorMessage::RecvDgramReadness {
                conn_handle,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    if conn.quiche_conn.dgram_recv_queue_len() > 0 {
                        let _ = respond_to.send(Ok(()));
                    } else {
                        conn.recv_dgram_readness_requests
                            .push_back(RecvDgramReadnessRequest { respond_to });
                    }
                } else {
                    let _ =
                        respond_to.send(Err(format!("No Connection: {:?}", conn_handle).into()));
                }
            }
            ActorMessage::RecvDgram {
                conn_handle,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    if conn.quiche_conn.dgram_recv_queue_len() > 0 {
                        let mut buf = BytesMut::with_capacity(1350);
                        buf.resize(1350, 0);
                        match conn.quiche_conn.dgram_recv(&mut buf) {
                            Ok(len) => {
                                buf.truncate(len);
                                let _ = respond_to.send(Ok(Some(buf.freeze())));
                            }
                            Err(e) if e == quiche::Error::Done => {
                                let _ = respond_to.send(Ok(None));
                            }
                            Err(e) => {
                                let _ = respond_to
                                    .send(Err(format!("dgram_recv failed: {:?}", e).into()));
                            }
                        }
                    } else {
                        let _ = respond_to.send(Ok(None));
                    }
                } else {
                    let _ =
                        respond_to.send(Err(format!("No Connection: {:?}", conn_handle).into()));
                }
            }
            ActorMessage::RecvDgramVectored {
                conn_handle,
                max_len,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    let mut bufs = Vec::new();
                    while conn.quiche_conn.dgram_recv_queue_len() > 0 {
                        if bufs.len() > max_len {
                            break;
                        }
                        let mut buf = BytesMut::with_capacity(1350);
                        buf.resize(1350, 0);
                        match conn.quiche_conn.dgram_recv(&mut buf) {
                            Ok(len) => {
                                buf.truncate(len);
                                bufs.push(buf.freeze());
                            }
                            Err(_) => {
                                break;
                            }
                        }
                    }
                    let _ = respond_to.send(Ok(bufs));
                } else {
                    let _ =
                        respond_to.send(Err(format!("No Connection: {:?}", conn_handle).into()));
                }
            }
            ActorMessage::RecvDgramInfo {
                conn_handle,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    let front_len = conn.quiche_conn.dgram_recv_front_len();
                    let queue_byte_size = conn.quiche_conn.dgram_recv_queue_byte_size();
                    let queue_len = conn.quiche_conn.dgram_recv_queue_len();

                    let _ = respond_to.send(Ok((front_len, queue_byte_size, queue_len)));
                } else {
                    let _ =
                        respond_to.send(Err(format!("No Connection: {:?}", conn_handle).into()));
                }
            }
            ActorMessage::SendStream {
                conn_handle,
                mut buf,
                stream_id,
                fin,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    match conn.quiche_conn.stream_send(stream_id, &buf, fin) {
                        Ok(written) => {
                            if written < buf.len() {
                                let buf = buf.split_off(written);
                                conn.send_stream_requests
                                    .entry(stream_id)
                                    .or_insert_with(|| VecDeque::new())
                                    .push_back(SendStreamRequest {
                                        buf,
                                        fin,
                                        respond_to,
                                    });
                            } else {
                                respond_to.send(Ok(())).ok();
                            }
                        }
                        Err(e) if e == quiche::Error::Done => {
                            conn.send_stream_requests
                                .entry(stream_id)
                                .or_insert_with(|| VecDeque::new())
                                .push_back(SendStreamRequest {
                                    buf,
                                    fin,
                                    respond_to,
                                });
                        }
                        Err(e) => {
                            respond_to
                                .send(Err(format!("dgram_send failed: {:?}", e).into()))
                                .ok();
                        }
                    }
                } else {
                    respond_to
                        .send(Err(format!("No Connection: {:?}", conn_handle).into()))
                        .ok();
                }
            }
            ActorMessage::SetStreamGroup {
                conn_handle,
                stream_id,
                group_id,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    match conn.quiche_conn.stream_group(stream_id, group_id) {
                        Ok(_) => {
                            respond_to.send(Ok(())).ok();
                        }
                        Err(e) => {
                            respond_to
                                .send(Err(format!("stream_group failed: {:?}", e).into()))
                                .ok();
                        }
                    }
                } else {
                    respond_to
                        .send(Err(format!("No Connection: {:?}", conn_handle).into()))
                        .ok();
                }
            }
            ActorMessage::SendDgram {
                conn_handle,
                buf,
                group_id,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    match conn.quiche_conn.dgram_send_group(&buf, group_id) {
                        Ok(_) => {
                            let _ = respond_to.send(Ok(()));
                        }
                        Err(e) if e == quiche::Error::Done => {
                            conn.send_dgram_requests.push_back(SendDgramRequest {
                                buf,
                                group_id,
                                respond_to,
                            });
                        }
                        Err(e) => {
                            let _ =
                                respond_to.send(Err(format!("dgram_send failed: {:?}", e).into()));
                        }
                    }
                } else {
                    let _ =
                        respond_to.send(Err(format!("No Connection: {:?}", conn_handle).into()));
                }
            }
            ActorMessage::Stats {
                conn_handle,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    let stats = conn.quiche_conn.stats();
                    let _ = respond_to.send(Ok(stats));
                } else {
                    let _ =
                        respond_to.send(Err(format!("No Connection: {:?}", conn_handle).into()));
                }
            }
            ActorMessage::PathStats {
                conn_handle,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    let stats = conn
                        .quiche_conn
                        .path_stats()
                        .collect::<Vec<quiche::PathStats>>();
                    let _ = respond_to.send(Ok(stats));
                } else {
                    let _ =
                        respond_to.send(Err(format!("No Connection: {:?}", conn_handle).into()));
                }
            }
            ActorMessage::Close {
                conn_handle,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    conn.quiche_conn.close(true, 0x00, b"").ok();
                    let _ = respond_to.send(Ok(()));
                } else {
                    let _ =
                        respond_to.send(Err(format!("No Connection: {:?}", conn_handle).into()));
                }
            }
            ActorMessage::ProbePath {
                conn_handle,
                local_addr,
                peer_addr,
                respond_to,
            } => {
                let socket_handle = self
                    .addrs_to_sockets
                    .iter()
                    .find(|(addr, _)| {
                        ((addr.is_ipv4() && local_addr.is_ipv4())
                            || (addr.is_ipv6() && local_addr.is_ipv6()))
                            && (addr.ip().is_unspecified() || addr.ip() == local_addr.ip())
                            && addr.port() == local_addr.port()
                    })
                    .map(|(_, handle)| *handle);
                let (socket_handle, local_addr) = if let Some(socket_handle) = socket_handle {
                    (socket_handle, local_addr)
                } else {
                    let local_addr = if local_addr.is_ipv4() {
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), local_addr.port())
                    } else {
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), local_addr.port())
                    };
                    let (socket_handle, binded_local) = match self.add_socket(local_addr).await {
                        Ok(v) => v,
                        Err(e) => {
                            let _ =
                                respond_to.send(Err(format!("get_binding failed: {:?}", e).into()));
                            return;
                        }
                    };
                    let new_local_addr = SocketAddr::new(local_addr.ip(), binded_local.port());
                    (socket_handle, new_local_addr)
                };
                let socket = self.sockets.get(&socket_handle).unwrap().clone();


                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    conn.locals_to_sockets.insert(local_addr, socket);

                    let _ = respond_to.send(Ok(local_addr));

                    match conn.quiche_conn.probe_path(local_addr, peer_addr) {
                        Ok(_v) => {}
                        Err(quiche::Error::OutOfIdentifiers) => {
                            if conn.quiche_conn.available_dcids() > 0 && conn.quiche_conn.source_cids_left() == 0 {
                                error!("cannot probe ({} {}): out of SCID", local_addr, peer_addr);
                            } else {
                                info!("wait probing ({} {}) until SCID or DCID available", local_addr, peer_addr);
                                conn.probe_path_requests.push_back(ProbePathRequest {
                                    local_addr,
                                    peer_addr,
                                });
                            }
                        }
                        Err(e) => {
                            error!("cannot probe ({} {}): {:?}", local_addr, peer_addr, e);
                        }
                    }
                } else {
                    let _ =
                        respond_to.send(Err(format!("No Connection: {:?}", conn_handle).into()));
                }
            }
            ActorMessage::PathEventReadness {
                conn_handle,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    if !conn.path_events.is_empty() {
                        let _ = respond_to.send(Ok(()));
                    } else {
                        conn.path_event_readness_requests
                            .push_back(PathEventReadnessRequest { respond_to });
                    }
                } else {
                    let _ =
                        respond_to.send(Err(format!("No Connection: {:?}", conn_handle).into()));
                }
            }
            ActorMessage::PathEvent {
                conn_handle,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    let event = conn.path_events.pop_front();
                    respond_to.send(Ok(event)).ok();
                } else {
                    let _ =
                        respond_to.send(Err(format!("No Connection: {:?}", conn_handle).into()));
                }
            }
            ActorMessage::InsertGroup {
                conn_handle,
                local_addr,
                peer_addr,
                group_id,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    match conn
                        .quiche_conn
                        .insert_group(local_addr, peer_addr, group_id)
                    {
                        Ok(v) => {
                            let _ = respond_to.send(Ok(v));
                        }
                        Err(e) => {
                            let _ =
                                respond_to
                                    .send(Err(format!("failed to insert_group: {:?}", e).into()));
                        }
                    }
                } else {
                    let _ =
                        respond_to.send(Err(format!("No Connection: {:?}", conn_handle).into()));
                }
            }
            ActorMessage::SetActive {
                conn_handle,
                local_addr,
                peer_addr,
                is_active,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    match conn
                        .quiche_conn
                        .set_active(local_addr, peer_addr, is_active)
                    {
                        Ok(v) => {
                            let _ = respond_to.send(Ok(v));
                        }
                        Err(e) => {
                            let _ = respond_to
                                .send(Err(format!("failed to set_active: {:?}", e).into()));
                        }
                    }
                } else {
                    let _ =
                        respond_to.send(Err(format!("No Connection: {:?}", conn_handle).into()));
                }
            }
        }
    }

    async fn handle_udp_dgram(
        &mut self,
        handle: SocketHandle,
        mut buf: BytesMut,
        from: SocketAddr,
        to: SocketAddr,
    ) {
        trace!("Recv UDP {} bytes", buf.len());

        let hdr = match quiche::Header::from_slice(&mut buf, quiche::MAX_CONN_ID_LEN) {
            Ok(v) => v,
            Err(e) => {
                error!("Parsing packet header failed: {:?}", e);
                return;
            }
        };

        let conn_handle = if !self.conn_ids.contains_key(&hdr.dcid) {
            if hdr.ty != quiche::Type::Initial {
                error!("Packet is not Initial");
                return;
            }
            let mut new_dcid = [0; quiche::MAX_CONN_ID_LEN];
            let new_dcid = &mut new_dcid[0..self.conn_id_len];
            SystemRandom::new().fill(&mut new_dcid[..]).unwrap();

            let new_dcid = quiche::ConnectionId::from_vec(new_dcid.into());

            let mut conn =
                quiche::accept(&new_dcid, None, to.clone(), from, &mut self.config).unwrap();

            if let Some(keylog) = &mut self.keylog {
                if let Ok(keylog) = keylog.try_clone() {
                    conn.set_keylog(Box::new(keylog));
                }
            }

            if let Some(dir) = std::env::var_os("QLOGDIR") {
                let writer = make_qlog_writer(&dir, "server", &conn.trace_id());

                conn.set_qlog(
                    std::boxed::Box::new(writer),
                    "quiche-server qlog".to_string(),
                    format!("{} id={}", "quiche-server qlog", conn.trace_id()),
                );
            }

            let socket = self.sockets.get(&handle).unwrap();
            let mut locals_to_sockets = HashMap::new();
            locals_to_sockets.insert(to, socket.clone());
            let new_conn_handle = self.next_conn_handle;

            self.conns.insert(
                new_conn_handle,
                QuicConnection {
                    quiche_conn: conn,
                    locals_to_sockets,
                    before_established: true,
                    wait_connected_request: None,
                    recv_stream_readness_requests: VecDeque::new(),
                    send_stream_requests: BTreeMap::new(),
                    recv_dgram_readness_requests: VecDeque::new(),
                    send_dgram_requests: VecDeque::new(),
                    probe_path_requests: VecDeque::new(),
                    path_events: VecDeque::new(),
                    path_event_readness_requests: VecDeque::new(),
                },
            );
            self.conn_ids.insert(new_dcid.clone(), new_conn_handle);
            self.next_conn_handle += 1;

            new_conn_handle
        } else {
            *self.conn_ids.get(&hdr.dcid).unwrap()
        };

        let recv_info = quiche::RecvInfo { from, to };
        // Process potentially coalesced packets.
        if let Some(conn) = self.conns.get_mut(&conn_handle) {
            if let Err(e) = conn.quiche_conn.recv(&mut buf, recv_info) {
                error!("{} recv() failed: {:?}", conn.quiche_conn.trace_id(), e);
            }

            if conn.quiche_conn.is_established() {
                if conn.before_established {
                    if let Some(queue) = &mut conn.wait_connected_request {
                        while let Some(request) = queue.pop_front() {
                            let _ = request.respond_to.send(Ok(()));
                        }
                    } else {
                        let res = conn.quiche_conn.peer_cert();
                        if self.client_cert_required && res.is_none() {
                            conn.quiche_conn
                                .close(false, 0x1, b"client cert required")
                                .ok();
                        } else {
                            let mut accepted = false;
                            while let Some(request) = self.accept_requests.pop_front() {
                                if let Ok(_) = request.respond_to.send(Ok(conn_handle)) {
                                    accepted = true;
                                    break;
                                }
                            }
                            if !accepted {
                                self.wait_conn_handles.push_back(conn_handle);
                            }
                        }
                    }
                    conn.before_established = false;
                }

                if conn.quiche_conn.dgram_recv_queue_len() > 0 {
                    while let Some(request) = conn.recv_dgram_readness_requests.pop_front() {
                        let _ = request.respond_to.send(Ok(()));
                    }
                }
            }
        } else {
            info!("No connection for conn_handle {}", conn_handle);
        }
    }

    async fn run(&mut self) {
        loop {
            let timeout = self
                .conns
                .values()
                .filter_map(|c| c.quiche_conn.timeout())
                .min();

            tokio::select! {
                Some((handle, (buf, from, to))) = self.recv_stream.next() => {
                    self.handle_udp_dgram(handle, buf, from, to).await;
                }
                maybe_msg = self.receiver.recv(), if !self.shutdown => {
                    if let Some(msg) = maybe_msg {
                        self.handle_message(msg).await;
                    } else {
                        info!("No handle exists!");
                        self.shutdown = true;
                        for conn in self.conns.values_mut() {
                            if !conn.quiche_conn.is_closed() && !conn.quiche_conn.is_draining() {
                                info!("{} Connection closed by shutdown process", conn.quiche_conn.trace_id());
                                conn.quiche_conn.close(false, 0x1, b"shutdown").ok();
                            }
                        }
                    }
                },
                _ = tokio::time::sleep(timeout.unwrap_or(Duration::from_millis(0))), if timeout.is_some() => {
                    info!("timeout");
                    self.conns.values_mut().for_each(|c| c.quiche_conn.on_timeout());
                }
            }

            for (conn_handle, conn) in self.conns.iter_mut() {
                if conn.quiche_conn.is_established() {
                    if !conn.recv_stream_readness_requests.is_empty()
                        && conn.quiche_conn.readable().next().is_some()
                    {
                        conn.recv_stream_readness_requests.retain_mut(|request| {
                            let filter = request.filter.clone().expect("not filled");
                            let readable = if let Some(stream_ids) = &request.stream_ids {
                                let stream_ids =
                                    stream_ids.iter().cloned().collect::<HashSet<u64>>();
                                let readable =
                                    conn.quiche_conn.readable().collect::<HashSet<u64>>();
                                stream_ids
                                    .intersection(&readable)
                                    .cloned()
                                    .filter(|id| match (*id & 0x03, filter) {
                                        (0x00, (true, _, _, _))
                                        | (0x01, (_, true, _, _))
                                        | (0x02, (_, _, true, _))
                                        | (0x03, (_, _, _, true)) => true,
                                        _ => false,
                                    })
                                    .collect::<Vec<u64>>()
                            } else {
                                conn.quiche_conn
                                    .readable()
                                    .filter(|id| match (*id & 0x03, filter) {
                                        (0x00, (true, _, _, _))
                                        | (0x01, (_, true, _, _))
                                        | (0x02, (_, _, true, _))
                                        | (0x03, (_, _, _, true)) => true,
                                        _ => false,
                                    })
                                    .collect::<Vec<u64>>()
                            };
                            if !readable.is_empty() {
                                if let Some(respond_to) = request.respond_to.take() {
                                    respond_to.send(Ok(readable)).ok();
                                }
                                false
                            } else {
                                true
                            }
                        });
                    }

                    if !conn.send_stream_requests.is_empty() {
                        let queued = conn
                            .send_stream_requests
                            .iter()
                            .map(|(id, _)| *id)
                            .collect::<HashSet<u64>>();
                        let writable = conn.quiche_conn.writable().collect::<HashSet<u64>>();
                        for stream_id in queued.intersection(&writable) {
                            if let btree_map::Entry::Occupied(mut entry) =
                                conn.send_stream_requests.entry(*stream_id)
                            {
                                let queue = entry.get_mut();
                                while let Some(mut request) = queue.pop_front() {
                                    match conn.quiche_conn.stream_send(
                                        *stream_id,
                                        &mut request.buf,
                                        request.fin,
                                    ) {
                                        Ok(written) => {
                                            if written < request.buf.len() {
                                                let buf = request.buf.split_off(written);
                                                queue.push_front(SendStreamRequest {
                                                    buf,
                                                    fin: request.fin,
                                                    respond_to: request.respond_to,
                                                });
                                                break;
                                            } else {
                                                request.respond_to.send(Ok(())).ok();
                                            }
                                        }
                                        Err(e) if e == quiche::Error::Done => {
                                            queue.push_front(request);
                                            break;
                                        }
                                        Err(e) => {
                                            request
                                                .respond_to
                                                .send(Err(
                                                    format!("stream_send failed: {:?}", e).into()
                                                ))
                                                .ok();
                                        }
                                    }
                                }
                                if queue.is_empty() {
                                    entry.remove();
                                }
                            }
                        }
                    }
                    while let Some(request) = conn.send_dgram_requests.pop_front() {
                        match conn
                            .quiche_conn
                            .dgram_send_group(&request.buf, request.group_id)
                        {
                            Ok(_) => {
                                let _ = request.respond_to.send(Ok(()));
                            }
                            Err(e) if e == quiche::Error::Done => {
                                conn.send_dgram_requests.push_front(request);
                                break;
                            }
                            Err(e) => {
                                let _ = request.respond_to.send(Err(format!(
                                    "dgram_send failed: {:?}",
                                    e
                                )
                                .into()));
                            }
                        }
                    }
                    while conn.quiche_conn.source_cids_left() > 0 {
                        let (new_scid, reset_token) =
                            generate_cid_and_reset_token(self.conn_id_len);

                        match conn
                            .quiche_conn
                            .new_source_cid(&new_scid, reset_token, false)
                        {
                            Ok(seq) => {
                                info!("new_source_cid: {:?} {} {}", &new_scid, reset_token, seq);
                            }
                            Err(e) => {
                                error!("Failed to new_source_cid: {:?}", e);
                                break;
                            }
                        }
                        self.conn_ids.insert(new_scid, *conn_handle);
                    }
                    if conn.quiche_conn.available_dcids() > 0 {
                        while let Some(request) = conn.probe_path_requests.pop_front() {
                            match conn
                                .quiche_conn
                                .probe_path(request.local_addr, request.peer_addr)
                            {
                                Ok(seq) => {
                                    info!("Probe ({} {}) with seq={}", request.local_addr, request.peer_addr, seq);
                                }
                                Err(quiche::Error::OutOfIdentifiers) => {
                                    if conn.quiche_conn.available_dcids() > 0 && conn.quiche_conn.source_cids_left() == 0 {
                                        error!("cannot probe ({} {}): out of SCID", request.local_addr, request.peer_addr);
                                    } else {
                                        info!("wait again probing ({} {}) until SCID or DCID available", request.local_addr, request.peer_addr);
                                        conn.probe_path_requests.push_front(request);
                                        break;
                                    }
                                }
                                Err(e) => {
                                    error!("cannot probe ({} {}): {:?}", request.local_addr, request.peer_addr, e);
                                }
                            }
                        }
                    }
                    while let Some(event) = conn.quiche_conn.path_event_next() {
                        conn.path_events.push_back(event);
                    }
                    if !conn.path_events.is_empty() {
                        while let Some(request) = conn.path_event_readness_requests.pop_front() {
                            request.respond_to.send(Ok(())).ok();
                        }
                    }
                }

                loop {
                    let (write, send_info) = match conn.quiche_conn.send(&mut self.out) {
                        Ok(v) => v,
                        Err(quiche::Error::Done) => {
                            break;
                        }
                        Err(e) => {
                            error!("{} send() failed: {:?}", conn.quiche_conn.trace_id(), e);
                            conn.quiche_conn.close(false, 0x1, b"fail").ok();
                            break;
                        }
                    };
                    let socket = conn.locals_to_sockets.get(&send_info.from).unwrap();
                    match send_sas(socket, &self.out[..write], &send_info.to, &send_info.from).await
                    {
                        Ok(written) => {
                            trace!("{} written {} bytes", conn.quiche_conn.trace_id(), written);
                        }
                        Err(e) => {
                            error!("{} send_sas() failed: {:?}", conn.quiche_conn.trace_id(), e);
                        }
                    }
                }
            }
            self.conns.retain(|conn_handle, c| {
                if !c.quiche_conn.is_closed() {
                    return true;
                }
                self.conn_ids.retain(|_, conn_handle1| {
                    *conn_handle != *conn_handle1
                });
                false
            });

            if self.shutdown && self.conns.is_empty() {
                info!("No connection exists.");
                break;
            }
        }
    }
}

impl Drop for QuicConnection {
    fn drop(&mut self) {
        if let Some(mut queue) = self.wait_connected_request.take() {
            for request in queue.drain(..) {
                let _ = request.respond_to.send(Err("Connection closed".into()));
            }
        }
        for request in self.recv_stream_readness_requests.drain(..) {
            if let Some(respond_to) = request.respond_to {
                let _ = respond_to.send(Err("Connection closed".into()));
            }
        }
        self.send_stream_requests.retain(|_, queue| {
            for request in queue.drain(..) {
                let _ = request.respond_to.send(Err("Connection closed".into()));
            }
            false
        });
        for request in self.recv_dgram_readness_requests.drain(..) {
            let _ = request.respond_to.send(Err("Connection closed".into()));
        }
        for request in self.send_dgram_requests.drain(..) {
            let _ = request.respond_to.send(Err("Connection closed".into()));
        }
        for request in self.path_event_readness_requests.drain(..) {
            let _ = request.respond_to.send(Err("Connection closed".into()));
        }
    }
}

#[derive(Clone)]
pub struct QuicHandle {
    sender: mpsc::Sender<ActorMessage>,
}

impl QuicHandle {
    pub fn new(
        config: quiche::Config,
        keylog: Option<File>,
        conn_id_len: usize,
        client_cert_required: bool,
        shutdown_complete: mpsc::Sender<()>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel(128);
        let mut actor = QuicActor::new(
            receiver,
            config,
            keylog,
            conn_id_len,
            client_cert_required,
            shutdown_complete,
        );

        tokio::spawn(async move {
            info!("Actor start");
            actor.run().await;
            info!("Actor End");
        });

        Self { sender }
    }

    pub async fn listen(&self, local: SocketAddr) -> Result<()> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::Listen {
            local,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        match recv.await.expect("Actor task has been killed") {
            Ok(v) => Ok(v),
            Err(e) => Err(e),
        }
    }

    pub async fn accept(&self) -> Result<QuicConnectionHandle> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::Accept { respond_to: send };
        let _ = self.sender.send(msg).await;
        match recv.await.expect("Actor task has been killed") {
            Ok(conn_handle) => Ok(QuicConnectionHandle {
                sender: self.sender.clone(),
                conn_handle,
            }),
            Err(e) => Err(e),
        }
    }

    pub async fn connect(
        &self,
        url: url::Url,
        local_addr: Option<SocketAddr>,
    ) -> Result<QuicConnectionHandle> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::Connect {
            url,
            local_addr,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        match recv.await.expect("Actor task has been killed") {
            Ok(conn_handle) => Ok(QuicConnectionHandle {
                sender: self.sender.clone(),
                conn_handle,
            }),
            Err(e) => Err(e),
        }
    }
}

#[derive(Clone)]
pub struct QuicConnectionHandle {
    sender: mpsc::Sender<ActorMessage>,
    pub conn_handle: ConnectionHandle,
}

impl QuicConnectionHandle {
    pub async fn wait_connected(&self) -> Result<()> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::WaitConnected {
            conn_handle: self.conn_handle,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn recv_stream_ready(
        &self,
        stream_ids: Option<Vec<u64>>,
        filter: Option<(bool, bool, bool, bool)>,
    ) -> Result<Vec<u64>> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::RecvStreamReadness {
            conn_handle: self.conn_handle,
            stream_ids,
            filter,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn recv_stream(&self, stream_id: u64) -> Result<Option<(Bytes, bool)>> {
        loop {
            let (send, recv) = oneshot::channel();
            let msg = ActorMessage::RecvStream {
                conn_handle: self.conn_handle,
                stream_id,
                respond_to: send,
            };
            let _ = self.sender.send(msg).await;
            match recv.await.expect("Actor task has been killed") {
                Ok(Some(buf)) => {
                    return Ok(Some(buf));
                }
                Ok(None) => {
                    let (send, recv) = oneshot::channel();
                    let msg = ActorMessage::RecvStreamReadness {
                        conn_handle: self.conn_handle,
                        stream_ids: Some(vec![stream_id]),
                        filter: None,
                        respond_to: send,
                    };
                    let _ = self.sender.send(msg).await;
                    let _ = recv.await.expect("Actor task has been killed");
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }

    pub async fn recv_dgram_ready(&self) -> Result<()> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::RecvDgramReadness {
            conn_handle: self.conn_handle,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn recv_dgram(&self) -> Result<Bytes> {
        loop {
            let (send, recv) = oneshot::channel();
            let msg = ActorMessage::RecvDgram {
                conn_handle: self.conn_handle,
                respond_to: send,
            };
            let _ = self.sender.send(msg).await;
            match recv.await.expect("Actor task has been killed") {
                Ok(Some(buf)) => {
                    return Ok(buf);
                }
                Ok(None) => {
                    let (send, recv) = oneshot::channel();
                    let msg = ActorMessage::RecvDgramReadness {
                        conn_handle: self.conn_handle,
                        respond_to: send,
                    };
                    let _ = self.sender.send(msg).await;
                    let _ = recv.await.expect("Actor task has been killed");
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }

    pub async fn recv_dgram_vectored(&self, max_len: usize) -> Result<Vec<Bytes>> {
        loop {
            let (send, recv) = oneshot::channel();
            let msg = ActorMessage::RecvDgramVectored {
                conn_handle: self.conn_handle,
                max_len,
                respond_to: send,
            };
            let _ = self.sender.send(msg).await;
            match recv.await.expect("Actor task has been killed") {
                Ok(bufs) => {
                    if !bufs.is_empty() {
                        return Ok(bufs);
                    }
                    let (send, recv) = oneshot::channel();
                    let msg = ActorMessage::RecvDgramReadness {
                        conn_handle: self.conn_handle,
                        respond_to: send,
                    };
                    let _ = self.sender.send(msg).await;
                    let _ = recv.await.expect("Actor task has been killed");
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }

    pub async fn recv_dgram_info(&self) -> Result<(Option<usize>, usize, usize)> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::RecvDgramInfo {
            conn_handle: self.conn_handle,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn send_stream(&self, buf: &Bytes, stream_id: u64, fin: bool) -> Result<()> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::SendStream {
            conn_handle: self.conn_handle,
            buf: buf.clone(),
            stream_id,
            fin,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn set_stream_group(&self, stream_id: u64, group_id: u64) -> Result<()> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::SetStreamGroup {
            conn_handle: self.conn_handle,
            stream_id,
            group_id,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn send_dgram(&self, buf: &Bytes, group_id: u64) -> Result<()> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::SendDgram {
            conn_handle: self.conn_handle,
            buf: buf.clone(),
            group_id,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn stats(&self) -> Result<quiche::Stats> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::Stats {
            conn_handle: self.conn_handle,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn path_stats(&self) -> Result<Vec<quiche::PathStats>> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::PathStats {
            conn_handle: self.conn_handle,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn probe_path(&self, local_addr: SocketAddr, peer_addr: SocketAddr) -> Result<SocketAddr> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::ProbePath {
            conn_handle: self.conn_handle,
            local_addr,
            peer_addr,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn path_event_ready(&self) -> Result<()> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::PathEventReadness {
            conn_handle: self.conn_handle,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn path_event(&self) -> Result<quiche::PathEvent> {
        loop {
            let (send, recv) = oneshot::channel();
            let msg = ActorMessage::PathEvent {
                conn_handle: self.conn_handle,
                respond_to: send,
            };
            let _ = self.sender.send(msg).await;
            match recv.await.expect("Actor task has been killed") {
                Ok(Some(event)) => {
                    return Ok(event);
                }
                Ok(None) => {
                    let (send, recv) = oneshot::channel();
                    let msg = ActorMessage::PathEventReadness {
                        conn_handle: self.conn_handle,
                        respond_to: send,
                    };
                    let _ = self.sender.send(msg).await;
                    let _ = recv.await.expect("Actor task has been killed");
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }
    pub async fn insert_group(
        &self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        group_id: u64,
    ) -> Result<bool> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::InsertGroup {
            conn_handle: self.conn_handle,
            local_addr,
            peer_addr,
            group_id,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn set_active(
        &self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        is_active: bool,
    ) -> Result<()> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::SetActive {
            conn_handle: self.conn_handle,
            local_addr,
            peer_addr,
            is_active,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn close(&self) -> Result<()> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::Close {
            conn_handle: self.conn_handle,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }
}

/// Makes a buffered writer for a qlog.
pub fn make_qlog_writer(
    dir: &std::ffi::OsStr,
    role: &str,
    id: &str,
) -> std::io::BufWriter<std::fs::File> {
    let mut path = std::path::PathBuf::from(dir);
    let filename = format!("{}-{}.sqlog", role, id);
    path.push(filename);

    match std::fs::File::create(&path) {
        Ok(f) => std::io::BufWriter::new(f),

        Err(e) => panic!(
            "Error creating qlog file attempted path was {:?}: {}",
            path, e
        ),
    }
}

fn generate_cid_and_reset_token(conn_id_len: usize) -> (quiche::ConnectionId<'static>, u128) {
    let mut scid = vec![0; conn_id_len];
    SystemRandom::new().fill(&mut scid[..]).unwrap();
    let scid = quiche::ConnectionId::from_vec(scid);
    let mut reset_token = [0; 16];
    SystemRandom::new().fill(&mut reset_token).unwrap();
    let reset_token = u128::from_be_bytes(reset_token);
    (scid, reset_token)
}

pub mod testing {
    use super::*;

    pub async fn open_server_with_config(
        config: quiche::Config,
        port: u16,
        shutdown_complete_tx: mpsc::Sender<()>,
    ) -> Result<QuicHandle> {
        let quic = QuicHandle::new(
            config,
            None,
            quiche::MAX_CONN_ID_LEN,
            false,
            shutdown_complete_tx.clone(),
        );

        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
        quic.listen(local).await.unwrap();
        let local = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), port);
        quic.listen(local).await.unwrap();
        Ok(quic)
    }

    pub async fn open_server(
        port: u16,
        shutdown_complete_tx: mpsc::Sender<()>,
    ) -> Result<QuicHandle> {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        config.load_cert_chain_from_pem_file("src/cert.crt")?;
        config.load_priv_key_from_pem_file("src/cert.key")?;
        config.set_application_protos(&[b"proto1"])?;
        config.set_max_idle_timeout(10000);
        config.set_max_recv_udp_payload_size(1350);
        config.set_max_send_udp_payload_size(1350);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);
        config.enable_early_data();
        config.enable_dgram(true, 1000, 1000);

        open_server_with_config(config, port, shutdown_complete_tx).await
    }

    pub fn open_client_with_config(
        config: quiche::Config,
        shutdown_complete_tx: mpsc::Sender<()>,
    ) -> Result<QuicHandle> {
        let quic = QuicHandle::new(
            config,
            None,
            quiche::MAX_CONN_ID_LEN,
            false,
            shutdown_complete_tx.clone(),
        );
        Ok(quic)
    }

    pub fn open_client(shutdown_complete_tx: mpsc::Sender<()>) -> Result<QuicHandle> {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        config.set_application_protos(&[b"proto1"])?;
        config.verify_peer(false);
        config.set_max_idle_timeout(10000);
        config.set_max_recv_udp_payload_size(1350);
        config.set_max_send_udp_payload_size(1350);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);
        config.enable_early_data();
        config.enable_dgram(true, 1000, 1000);

        open_client_with_config(config, shutdown_complete_tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_v4() {
        let (shutdown_complete_tx, _) = mpsc::channel(1);
        let _server = testing::open_server(12345, shutdown_complete_tx.clone())
            .await
            .unwrap();
        let client = testing::open_client(shutdown_complete_tx.clone()).unwrap();
        let url = url::Url::parse("http://127.0.0.1:12345").unwrap();
        let res = client.connect(url, None).await;
        assert_eq!(res.is_ok(), true);
        let conn = res.unwrap();
        let res = conn.wait_connected().await;
        assert_eq!(res.is_ok(), true);
    }

    #[tokio::test]
    async fn connect_v6() {
        let (shutdown_complete_tx, _) = mpsc::channel(1);
        let _server = testing::open_server(12346, shutdown_complete_tx.clone())
            .await
            .unwrap();
        let client = testing::open_client(shutdown_complete_tx.clone()).unwrap();
        let url = url::Url::parse("http://[::1]:12346").unwrap();
        let res = client.connect(url, None).await;
        assert_eq!(res.is_ok(), true);
        let conn = res.unwrap();
        let res = conn.wait_connected().await;
        assert_eq!(res.is_ok(), true);
    }

    #[tokio::test]
    async fn accept_v4() {
        let (shutdown_complete_tx, _) = mpsc::channel(1);
        let server = testing::open_server(12347, shutdown_complete_tx.clone())
            .await
            .unwrap();
        let client = testing::open_client(shutdown_complete_tx.clone()).unwrap();
        let url = url::Url::parse("http://127.0.0.1:12347").unwrap();
        let _ = client.connect(url, None).await;
        let res = server.accept().await;
        assert_eq!(res.is_ok(), true);
    }

    #[tokio::test]
    async fn accept_v6() {
        let (shutdown_complete_tx, _) = mpsc::channel(1);
        let server = testing::open_server(12348, shutdown_complete_tx.clone())
            .await
            .unwrap();
        let client = testing::open_client(shutdown_complete_tx.clone()).unwrap();
        let url = url::Url::parse("http://[::1]:12348").unwrap();
        let _ = client.connect(url, None).await;
        let res = server.accept().await;
        assert_eq!(res.is_ok(), true);
    }

    #[tokio::test]
    async fn stream() {
        let (shutdown_complete_tx, _) = mpsc::channel(1);
        let server = testing::open_server(12349, shutdown_complete_tx.clone())
            .await
            .unwrap();
        let client = testing::open_client(shutdown_complete_tx.clone()).unwrap();
        let url = url::Url::parse("http://127.0.0.1:12349").unwrap();
        let conn = client.connect(url, None).await.unwrap();
        conn.wait_connected().await.unwrap();
        let conn1 = server.accept().await.unwrap();

        let buf = Bytes::from("hello");
        let ret = conn.send_stream(&buf, 0, true).await;
        assert_eq!(ret.is_ok(), true);
        let ret = conn1.recv_stream_ready(None, None).await;
        assert_eq!(ret.is_ok(), true);
        let readable = ret.unwrap();
        assert_eq!(readable, vec![0]);
        let ret = conn1.recv_stream(0).await;
        assert_eq!(ret.is_ok(), true);
        let ret = ret.unwrap();
        assert_eq!(ret.is_some(), true);
        let (buf1, fin) = ret.unwrap();
        assert_eq!(buf, buf1);
        assert_eq!(fin, true);
    }

    #[tokio::test]
    async fn stream_with_short_buf() {
        let (shutdown_complete_tx, _) = mpsc::channel(1);
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("src/cert.crt")
            .unwrap();
        config.load_priv_key_from_pem_file("src/cert.key").unwrap();
        config.set_application_protos(&[b"proto1"]).unwrap();
        config.set_initial_max_data(6);
        config.set_initial_max_stream_data_bidi_local(6);
        config.set_initial_max_stream_data_bidi_remote(6);
        config.set_initial_max_stream_data_uni(10);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);

        let server = testing::open_server_with_config(config, 12349, shutdown_complete_tx.clone())
            .await
            .unwrap();
        let client = testing::open_client(shutdown_complete_tx.clone()).unwrap();
        let url = url::Url::parse("http://127.0.0.1:12349").unwrap();
        let conn = client.connect(url, None).await.unwrap();
        conn.wait_connected().await.unwrap();
        let conn1 = server.accept().await.unwrap();

        tokio::task::spawn(async move {
            let ret = conn1.recv_stream_ready(None, None).await;
            assert_eq!(ret.is_ok(), true);
            let readable = ret.unwrap();
            assert_eq!(readable, vec![0]);
            let ret = conn1.recv_stream(0).await;
            assert_eq!(ret.is_ok(), true);
            let ret = ret.unwrap();
            assert_eq!(ret.is_some(), true);
            let (buf1, fin) = ret.unwrap();
            assert_eq!(buf1, Bytes::from("hello "));
            assert_eq!(fin, false);

            let ret = conn1.recv_stream_ready(None, None).await;
            assert_eq!(ret.is_ok(), true);
            let readable = ret.unwrap();
            assert_eq!(readable, vec![0]);
            let ret = conn1.recv_stream(0).await;
            assert_eq!(ret.is_ok(), true);
            let ret = ret.unwrap();
            assert_eq!(ret.is_some(), true);
            let (buf1, fin) = ret.unwrap();
            assert_eq!(buf1, Bytes::from("world"));
            assert_eq!(fin, true);
        });

        let buf = Bytes::from("hello world");
        let ret = conn.send_stream(&buf, 0, true).await;
        assert_eq!(ret.is_ok(), true);
    }

    #[tokio::test]
    async fn dgram() {
        let (shutdown_complete_tx, _) = mpsc::channel(1);
        let server = testing::open_server(12349, shutdown_complete_tx.clone())
            .await
            .unwrap();
        let client = testing::open_client(shutdown_complete_tx.clone()).unwrap();
        let url = url::Url::parse("http://127.0.0.1:12349").unwrap();
        let conn = client.connect(url, None).await.unwrap();
        conn.wait_connected().await.unwrap();
        let conn1 = server.accept().await.unwrap();

        let buf = Bytes::from("hello");
        conn.send_dgram(&buf, 0).await.unwrap();
        let ret = conn1.recv_dgram().await;
        assert_eq!(ret.is_ok(), true);
        let buf1 = ret.unwrap();
        assert_eq!(buf, buf1);
    }
}
