use crate::quic::*;
use crate::tap::Tap;
use bytes::BytesMut;
use pcap_file::pcap::PcapWriter;
use std::fs::{File, OpenOptions};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::sync::{broadcast, mpsc};
use tokio::time::sleep;

pub async fn transfer(
    quic: QuicConnectionHandle,
    notify_shutdown: broadcast::Receiver<()>,
    notify_shutdown1: broadcast::Receiver<()>,
    shutdown_complete: mpsc::Sender<()>,
    enable_pktlog: bool,
    show_stats: bool,
) {
    if let Ok(tap) = Tap::new() {
        let tap = Arc::new(tap);
        let pcap_writer = if enable_pktlog {
            let path = format!(
                "{}.pcap",
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            );
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .open(path)
                .unwrap();

            let pcap_writer = PcapWriter::new(file).unwrap();
            Some(Arc::new(Mutex::new(pcap_writer)))
        } else {
            None
        };

        info!(
            "Transfer starts: ConnectionHandle: {}, Tap: {:?}",
            quic.conn_handle, &tap
        );
        let quic1 = quic.clone();
        let quic2 = quic.clone();
        let tap1 = tap.clone();
        let tap2 = tap.clone();
        let pcap_writer1 = pcap_writer.clone();
        let shutdown_complete1 = shutdown_complete.clone();
        let mut task = tokio::spawn(async move {
            remote_to_local(quic, tap1, pcap_writer, notify_shutdown, shutdown_complete).await;
        });
        let mut task1 = tokio::spawn(async move {
            local_to_remote(
                quic1,
                tap2,
                pcap_writer1,
                notify_shutdown1,
                shutdown_complete1,
            )
            .await;
        });
        let mut task_finished = false;
        let mut task1_finished = false;
        loop {
            tokio::select! {
                _ = &mut task, if !task_finished => {
                    task_finished = true;
                }
                _ = &mut task1, if !task1_finished => {
                    task1_finished = true;
                }
                _ = sleep(Duration::from_secs(1)), if show_stats => {
                    if let Ok(stats) = quic2.stats().await {
                        info!("lost: {}", stats.lost);
                    }
                    if let Ok(paths) = quic2.path_stats().await {
                        for stats in paths {
                            info!("local_addr: {}, peer_addr: {}, rtt: {:?}, cwnd: {} bytes, delivery_rate: {:.3} Mbps",
                                stats.local_addr,
                                stats.peer_addr,
                                stats.rtt,
                                stats.cwnd,
                                stats.delivery_rate as f64 * 8.0 / (1024.0 * 1024.0)
                            );
                        }
                    }
                    if let Ok((front_len, queue_byte_size, queue_len)) = quic2.recv_dgram_info().await {
                        info!(
                            "front_len: {} bytes, queue_byte_size: {} bytes, queue_len: {} counts",
                            front_len.unwrap_or(0),
                            queue_byte_size,
                            queue_len
                        );
                    }
                }
            }
            if task_finished && task1_finished {
                break;
            }
        }
        info!("Transfer ends: Tap: {:?}", &tap);
    }
}

async fn remote_to_local(
    quic: QuicConnectionHandle,
    tap: Arc<Tap>,
    pcap_writer: Option<Arc<Mutex<PcapWriter<File>>>>,
    mut notify_shutdown: broadcast::Receiver<()>,
    _shutdown_complete: mpsc::Sender<()>,
) {
    'main: loop {
        tokio::select! {
            _ = quic.recv_dgram_ready() => {
                let ret = quic.recv_dgram_vectored(usize::MAX).await;
                match ret {
                    Ok(bufs) => {
                        for buf in bufs {
                            trace!("{:?} Recv dgram {} bytes", std::thread::current().id(), buf.len());
                            if let Some(pcap_writer) = &pcap_writer {
                                if let Ok(mut pcap_writer) = pcap_writer.lock() {
                                    let time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
                                    let ts_sec = time.as_secs().try_into().unwrap();
                                    let ts_nsec = time.subsec_nanos();
                                    let orig_len = buf.len().try_into().unwrap();
                                    pcap_writer.write(ts_sec, ts_nsec, &buf[..], orig_len).unwrap();
                                }
                            }
                            match tap.write(&buf[..]).await {
                                Ok(n) => {
                                    trace!("Write packet {} bytes", n);
                                }
                                Err(e) => {
                                    error!("Write failed {:?}", e);
                                    break 'main;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Recv dgram failed: {:?}", e);
                        break 'main;
                    }
                }
            },
            _ = notify_shutdown.recv() => {
                break 'main;
            },
        }
    }
}

async fn local_to_remote(
    quic: QuicConnectionHandle,
    tap: Arc<Tap>,
    pcap_writer: Option<Arc<Mutex<PcapWriter<File>>>>,
    mut notify_shutdown: broadcast::Receiver<()>,
    _shutdown_complete: mpsc::Sender<()>,
) {
    'main: loop {
        let mut buf = BytesMut::with_capacity(1350);
        buf.resize(1350, 0);
        tokio::select! {
            res = tap.read(&mut buf[..]) => {
                match res {
                    Ok(n) => {
                        buf.truncate(n);
                        trace!("{:?} Read packet {} bytes", std::thread::current().id(), n);
                        if let Some(pcap_writer) = &pcap_writer {
                            if let Ok(mut pcap_writer) = pcap_writer.lock() {
                                let time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
                                let ts_sec = time.as_secs().try_into().unwrap();
                                let ts_nsec = time.subsec_nanos();
                                let orig_len = buf.len().try_into().unwrap();
                                pcap_writer.write(ts_sec, ts_nsec, &buf[..], orig_len).unwrap();
                            }
                        }
                        let buf = buf.freeze();
                        match quic.send_dgram(&buf).await {
                            Ok(_) => {
                                trace!("Send dgram {} bytes", n);
                            }
                            Err(e) => {
                                error!("Send dgram failed: {:?}", e);
                                break 'main;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Read failed {:?}", e);
                        break 'main;
                    }
                }
            },
            _ = notify_shutdown.recv() => {
                break 'main;
            },
        }
    }
}
