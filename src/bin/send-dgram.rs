extern crate env_logger;

use bytes::BytesMut;
use rqst::quic::*;
use std::env;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc};

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let mut args = env::args();
    let cmd = &args.next().unwrap();
    if args.len() != 1 {
        println!("Usage: {} URL", cmd);
        return Ok(());
    }
    let url = url::Url::parse(&args.next().unwrap()).unwrap();

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config.verify_peer(false);

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

    let mut notify_shutdown_rx: broadcast::Receiver<()> = notify_shutdown.subscribe();
    let shutdown_complete_tx1 = shutdown_complete_tx.clone();

    let task = tokio::spawn(async move {
        let _shutdown_complete_tx1 = shutdown_complete_tx1;

        println!("connecting to {}", &url);
        let conn = quic.connect(url, None).await.unwrap();
        tokio::select! {
            ret = conn.wait_connected() => {
                match ret {
                    Ok(_) => {
                        println!("Connection established: {}", conn.conn_handle);
                   },
                   Err(e) => {
                       println!("connect failed: {:?}", e);
                       return;
                   }
                }
            },
            _ = notify_shutdown_rx.recv() => {
                println!("connect canceled!");
                return;
            },
        };

        if let Ok(paths) = conn.path_stats().await {
            assert_eq!(paths.len(), 1);
            let mut local_addr = paths[0].local_addr;
            let peer_addr = paths[0].peer_addr;

            conn.insert_group(local_addr, peer_addr, 1).await.ok();

            local_addr.set_port(local_addr.port() + 1);
            match conn.probe_path(local_addr, peer_addr).await {
                Ok(_) => {
                    println!("Request probing ({} {})", local_addr, peer_addr);
                }
                Err(e) => {
                    println!("failed to probe_path: {:?}", e);
                }
            }
        }
        println!("enter loop");
        let mut now = Instant::now();
        let mut count: u8 = 0;
        loop {
            if Instant::now().duration_since(now) >= Duration::from_secs(1) {
                if let Ok(stats) = conn.stats().await {
                    println!("lost: {}", stats.lost);   
                }
                if let Ok(paths) = conn.path_stats().await {
                    println!(
                        "rtt: {:?}, cwnd: {} bytes, delivery_rate: {:.3} Mbps",
                        paths[0].rtt,
                        paths[0].cwnd,
                        paths[0].delivery_rate as f64 * 8.0 / (1024.0 * 1024.0)
                    );                    
                }
                now = Instant::now();
            }
            let mut buf = BytesMut::with_capacity(1292);
            buf.resize(1292, count);
            let buf = buf.freeze();
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    let res = if count % 2 == 0 {
                        conn.send_dgram(&buf, 1).await
                    } else {
                        conn.send_dgram(&buf, 2).await
                    };
                    match res {
                        Ok(_) => {
                            if let Some(new_count) = count.checked_add(1) {
                                count = new_count;
                            } else {
                                count = 0;
                            }
                        }
                        Err(e) => {
                            println!("Send failed: {:?}", e);
                            break;
                        }
                    }
                }
                res = conn.path_event() => {
                    match res {
                        Ok(event) => {
                            match event {
                                quiche::PathEvent::New(..) => unreachable!(),

                                quiche::PathEvent::Validated(local_addr, peer_addr) => {
                                    println!("Path ({}, {}) is now validated", local_addr, peer_addr);
                                    conn.set_active(local_addr, peer_addr, true).await.ok();
                                }

                                quiche::PathEvent::ReturnAvailable(local_addr, peer_addr) => {
                                    println!("Path ({}, {})'s return is now available", local_addr, peer_addr);
                                    conn.insert_group(local_addr, peer_addr, 2).await.ok();
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

                                quiche::PathEvent::PeerMigrated(..) => unreachable!(),

                                quiche::PathEvent::PeerPathStatus(..) => {},

                                quiche::PathEvent::InsertGroup(..) => unreachable!(),

                                quiche::PathEvent::RemoveGroup(..) => unreachable!(),
                            }
                        }
                        Err(e) => {
                            println!("path_event failed: {:?}", e);
                        }
                    }
                },
                _ = notify_shutdown_rx.recv() => {
                    break;
                }
            }
        }
        println!("leave loop");
        conn.close().await.unwrap();
    });

    tokio::select! {
        _ = task => {},
        _ = tokio::signal::ctrl_c() => {
            drop(notify_shutdown);
        }
    }
    drop(shutdown_complete_tx);
    let _ = shutdown_complete_rx.recv().await;
    Ok(())
}
