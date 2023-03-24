extern crate env_logger;

use rqst::quic::*;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc};
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config.verify_peer(false);

    config
        .load_cert_chain_from_pem_file("src/cert.crt")
        .unwrap();
    config.load_priv_key_from_pem_file("src/cert.key").unwrap();

    config.set_application_protos(&[b"vpn"]).unwrap();

    config.set_max_idle_timeout(0);
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
    config.set_multipath(true);

    let mut keylog = None;

    if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(keylog_path)
            .unwrap();

        keylog = Some(file);

        config.log_keys();
    }

    let (notify_shutdown, _) = broadcast::channel(1);
    let (shutdown_complete_tx, mut shutdown_complete_rx) = mpsc::channel(1);

    let quic = QuicHandle::new(
        config,
        keylog,
        quiche::MAX_CONN_ID_LEN,
        false,
        shutdown_complete_tx.clone(),
    );

    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4433);
    quic.listen(local).await.unwrap();
    let local = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 4433);
    quic.listen(local).await.unwrap();

    loop {
        tokio::select! {
            Ok(conn) = quic.accept() => {
                println!("Connection accepted: {}", conn.conn_handle);
                let mut notify_shutdown_rx: broadcast::Receiver<()> = notify_shutdown.subscribe();
                let shutdown_complete_tx1 = shutdown_complete_tx.clone();
                tokio::spawn( async move {
                    let _shutdown_complete_tx1 = shutdown_complete_tx1;

                    println!("enter loop");
                    let mut now = Instant::now();
                    let mut bytes = 0;
                    loop {
                        let elapsed = Instant::now().duration_since(now);
                        if elapsed >= Duration::from_secs(1) {
                            if let Ok((front_len, queue_byte_size, queue_len)) = conn.recv_dgram_info().await {
                                println!(
                                    "front_len: {} bytes, queue_byte_size: {} bytes, queue_len: {} counts",
                                    front_len.unwrap_or(0),
                                    queue_byte_size,
                                    queue_len
                                );
                                now = Instant::now();
                            }
                            println!("{:.3} Mbps", bytes as f64 * 8.0 / (1024.0 * 1024.0) / elapsed.as_secs_f64());
                            bytes = 0;
                        }
                        tokio::select! {
                            _ = conn.recv_dgram_ready() => {
                                let ret = conn.recv_dgram_vectored(1).await;
                                match ret {
                                    Ok(bufs) => {
                                        bytes += bufs.iter().map(|x| x.len()).sum::<usize>();
                                    }
                                    Err(e) => {
                                        println!("recv_dgram: failed: {:?}", e);
                                        break;
                                    }
                                }
                            },
                            res = conn.path_event() => {
                                match res {
                                    Ok(event) => {
                                        match event {
                                            quiche::PathEvent::New(local_addr, peer_addr) => {
                                                println!("Seen new Path ({}, {})", local_addr, peer_addr);
                                            },
            
                                            quiche::PathEvent::Validated(local_addr, peer_addr) => {
                                                println!("Path ({}, {}) is now validated", local_addr, peer_addr);
                                                conn.set_active(local_addr, peer_addr, true).await.ok();
                                            }
            
                                            quiche::PathEvent::ReturnAvailable(local_addr, peer_addr) => {
                                                println!("Path ({}, {})'s return is now available", local_addr, peer_addr);
                                            }
                                            
                                            quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                                                println!("Path ({}, {}) failed validation", local_addr, peer_addr);
                                            }
            
                                            quiche::PathEvent::Closed(local_addr, peer_addr, e, reason) => {
                                                println!("Path ({}, {}) is now closed and unusable; err = {}, reason = {:?}",
                                                    local_addr, peer_addr, e, reason);
                                            }
            
                                            quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                                                println!("Peer reused cid seq {} (initially {:?}) on {:?}",
                                                    cid_seq, old, new);
                                            }
            
                                            quiche::PathEvent::PeerMigrated(..) => {},
            
                                            quiche::PathEvent::PeerPathStatus(..) => {},
            
                                            quiche::PathEvent::InsertGroup(group_id, (local_addr, peer_addr)) => {
                                                println!("Peer inserts path ({}, {}) into group {}",
                                                    local_addr, peer_addr, group_id);
                                            },
            
                                            quiche::PathEvent::RemoveGroup(..) => unreachable!(),
                                        }
                                    }
                                    Err(e) => {
                                        println!("path_event failed: {:?}", e);
                                    }
                                }
                            },
            
                            _ = tokio::time::sleep(Duration::from_secs(0)) => {}
                            _ = notify_shutdown_rx.recv() => {
                                println!("leave loop");
                                break;
                            }
                        }
                    }
                    conn.close().await.unwrap();
                    println!("leave loop");
                });
            },
            _ = tokio::signal::ctrl_c() => {
                drop(notify_shutdown);
                break;
            },
        };
    }
    drop(quic);
    drop(shutdown_complete_tx);
    let _ = shutdown_complete_rx.recv().await;
    Ok(())
}
