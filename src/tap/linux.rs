use std::fmt;
use std::io;
use tokio_tun::{Tun, TunBuilder};

pub struct Tap {
    inner: Tun,
}

impl Tap {
    pub fn new() -> io::Result<Tap> {
        let res = TunBuilder::new()
            .name("tap0")
            .packet_info(false)
            .tap(true)
            .try_build();
        match res {
            Ok(inner) => Ok(Tap { inner }),
            Err(_e) => {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "No available Tap I/F",
                ))
            }
        }
    }

    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.recv(buf).await
    }

    pub async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.inner.send(buf).await
    }
}

impl fmt::Debug for Tap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "name: {}", self.inner.name())
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
