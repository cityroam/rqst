use std::fs::OpenOptions;
use std::io;
use std::os::windows::prelude::*;
use tokio::net::windows::named_pipe;
use windows_sys::{Win32::Storage::FileSystem::*, Win32::System::IO::*};
use winreg::enums::*;
use winreg::RegKey;

const TAP_WIN_IOCTL_SET_MEDIA_STATUS: u32 = 0x00000022 << 16 | 0 << 14 | 6 << 2 | 0;

#[derive(Debug)]
pub struct Tap {
    inner: named_pipe::NamedPipeClient,
}

impl Tap {
    pub fn new() -> io::Result<Tap> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let net_adapter = hklm.open_subkey(
            "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}",
        )?;
        let instance_ids = net_adapter
            .enum_keys()
            .filter_map(|x| {
                if let Ok(name) = x {
                    if let Ok(entry) = net_adapter.open_subkey(name) {
                        if let Ok(component_id) = entry.get_value::<String, &str>("ComponentId") {
                            if component_id == "root\\tap0901" {
                                if let Ok(instance_id) =
                                    entry.get_value::<String, &str>("NetCfgInstanceId")
                                {
                                    return Some(instance_id);
                                }
                            }
                        }
                    }
                }
                None
            })
            .collect::<Vec<String>>();

        let res = instance_ids
            .iter()
            .filter_map(|instance_id| {
                match OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(false)
                    .attributes(FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED)
                    .open(format!("\\\\.\\Global\\{}.tap", instance_id))
                {
                    Ok(file) => Some(file),
                    Err(_) => None,
                }
            })
            .next();

        let file = if let Some(file) = res {
            file
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No available Tap I/F",
            ));
        };

        let mut info: [u32; 1] = [1; 1];
        let mut len: u32 = 0;
        unsafe {
            if DeviceIoControl(
                file.as_raw_handle() as isize,
                TAP_WIN_IOCTL_SET_MEDIA_STATUS,
                info.as_mut_ptr() as _,
                4,
                info.as_mut_ptr() as _,
                4,
                &mut len,
                std::ptr::null_mut(),
            ) != 0
            {
                let inner =
                    named_pipe::NamedPipeClient::from_raw_handle(file.into_raw_handle()).unwrap();
                Ok(Tap { inner })
            } else {
                return Err(std::io::Error::last_os_error());
            }
        }
    }

    pub async fn readable(&self) -> io::Result<()> {
        self.inner.readable().await
    }

    pub fn try_read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.try_read(buf)
    }

    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let _ = self.inner.readable().await;
            match self.inner.try_read(buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    pub async fn writable(&self) -> io::Result<()> {
        self.inner.writable().await
    }

    pub fn try_write(&self, buf: &[u8]) -> io::Result<usize> {
        self.inner.try_write(buf)
    }

    pub async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let _ = self.inner.writable().await;
            match self.inner.try_write(buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_open_tap() {
        let mut taps = Vec::new();
        loop {
            let res = Tap::new();
            if let Ok(tap) = res {
                taps.push(tap);
            } else {
                break;
            }
        }
        assert!(taps.len() > 0);
    }

    #[tokio::test]
    async fn test_read_tap() {
        let tap = Tap::new().unwrap();

        let mut buf = vec![0u8; 2048];
        for _ in 0..10 {
            let n = tap.read(&mut buf).await.unwrap();
            assert!(n > 0);
        }
    }

    #[tokio::test]
    async fn test_write_tap() {
        let tap = Tap::new().unwrap();

        let icmp_echo: [u8; 74] = [
            0x00, 0xff, 0x4b, 0x1e, 0x62, 0x4a, 0xfc, 0x34, 0x97, 0x97, 0x4f, 0xed, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x3c, 0x34, 0xf0, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0xac, 0x11,
            0xff, 0x02, 0xac, 0x11, 0xff, 0x01, 0x08, 0x00, 0x4d, 0x2b, 0x00, 0x01, 0x00, 0x30,
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
            0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65,
            0x66, 0x67, 0x68, 0x69,
        ];
        for _ in 0..10 {
            let n = tap.write(&icmp_echo).await.unwrap();
            assert!(n == 74);
        }
    }
}
