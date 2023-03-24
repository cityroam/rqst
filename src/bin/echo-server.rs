extern crate env_logger;

use anyhow::{anyhow, Context};
use log::{error, info};
use rqst::{quic::*, vpn::*};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    let mut set = JoinSet::new();
    loop {
        tokio::select! {
            Ok(conn) = quic.accept() => {
                info!("Connection accepted: {}", conn.conn_handle);
                let notify_shutdown_rx = notify_shutdown.subscribe();
                let shutdown_complete_tx1 = shutdown_complete_tx.clone();
                set.spawn( async move {
                    process_client(conn, notify_shutdown_rx, shutdown_complete_tx1).await
                });
            },
            res = set.join_next(), if !set.is_empty() => {
                if let Some(res) = res {
                    match res? {
                        Ok(_) => {
                            info!("process_client() successfuly finish.");
                        }
                        Err(e) => {
                            error!("Error occured in process_client(): {:?}", e);
                        }
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Request shutdown.");
                drop(notify_shutdown);
                while let Some(res) = set.join_next().await {
                    if let Err(e) = res? {
                        error!("Error occured in process_client(): {:?}", e);
                    }
                }
                break;
            },
        };
    }
    drop(quic);
    drop(shutdown_complete_tx);
    let _ = shutdown_complete_rx.recv().await;
    Ok(())
}

async fn process_client(
    conn: QuicConnectionHandle,
    mut notify_shutdown: broadcast::Receiver<()>,
    shutdown_complete: mpsc::Sender<()>,
) -> anyhow::Result<()> {
    info!("Enter loop");
    let mut ctrlmng = ControlManager::new(true);
    let mut notify_shutdown_subprocess = None;
    let mut set = JoinSet::new();

    loop {
        tokio::select! {
            //res = conn.recv_stream_ready(None, None) => {
            res = conn.recv_stream_ready(None, Some((true, false, false, false))) => {
                let readable = res.map_err(|e| anyhow!(e))
                    .context("check stream's readness")?;
                for stream_id in readable {
                    match ctrlmng.recv_request(&conn, stream_id).await.with_context(|| format!("receive and parse request in {} stream", stream_id))? {
                        Some((seq, RequestMsg::Start)) => {
                            info!("Recv start request");
                            let (notify_shutdown_tx, notify_shutdown_rx) = broadcast::channel(1);
                            notify_shutdown_subprocess = Some(notify_shutdown_tx);
                            let conn1 = conn.clone();
                            let shutdown_complete1 = shutdown_complete.clone();
                            set.spawn(async move {
                                subprocess_client(conn1, notify_shutdown_rx, shutdown_complete1).await
                            });
                            ctrlmng.send_response_ok(&conn, seq).await?;
                        }
                        Some((seq, RequestMsg::Stop)) => {
                            info!("Recv stop request");
                            if let Some(notify) = notify_shutdown_subprocess.take() {
                                drop(notify);
                                ctrlmng.send_response_ok(&conn, seq).await?;
                            } else {
                                ctrlmng.send_response_err(&conn, seq, "Not running").await?;
                            }
                        }
                        _ => {}
                    }
                }
            }
            res = conn.path_event() => {
                let event = res.map_err(|e| anyhow!(e))
                    .context("path_event()")?;
                match event {
                    quiche::PathEvent::New(local_addr, peer_addr) => {
                        info!("Seen new Path ({}, {})", local_addr, peer_addr);
                    },

                    quiche::PathEvent::Validated(local_addr, peer_addr) => {
                        info!("Path ({}, {}) is now validated", local_addr, peer_addr);
                        conn.set_active(local_addr, peer_addr, true).await.ok();
                    }

                    quiche::PathEvent::ReturnAvailable(local_addr, peer_addr) => {
                        info!("Path ({}, {})'s return is now available", local_addr, peer_addr);
                    }

                    quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                        info!("Path ({}, {}) failed validation", local_addr, peer_addr);
                    }

                    quiche::PathEvent::Closed(local_addr, peer_addr, e, reason) => {
                        info!("Path ({}, {}) is now closed and unusable; err = {}, reason = {:?}",
                            local_addr, peer_addr, e, reason);
                    }

                    quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                        info!("Peer reused cid seq {} (initially {:?}) on {:?}",
                            cid_seq, old, new);
                    }

                    quiche::PathEvent::PeerMigrated(..) => {},

                    quiche::PathEvent::PeerPathStatus(..) => {},

                    quiche::PathEvent::InsertGroup(group_id, (local_addr, peer_addr)) => {
                        info!("Peer inserts path ({}, {}) into group {}",
                            local_addr, peer_addr, group_id);
                    },

                    quiche::PathEvent::RemoveGroup(..) => unreachable!(),
                }
            },

            res = set.join_next(), if !set.is_empty() => {
                if let Some(res) = res {
                    match res? {
                        Ok(_) => {
                            info!("subprocess_client() successfuly finish");
                        }
                        Err(e) => {
                            info!("Error occured in subprocess_client(): {:?}", e);
                        }
                    }
                }
            }
            _ = notify_shutdown.recv() => {
                info!("Shutdown requested");
                drop(notify_shutdown_subprocess);
                while let Some(res) = set.join_next().await {
                    if let Err(e) = res? {
                        error!("Error occured in process_client(): {:?}", e);
                    }
                }
                break;
            }
        }
    }
    conn.close().await.unwrap();
    info!("leave loop");
    Ok(())
}

async fn subprocess_client(
    conn: QuicConnectionHandle,
    mut notify_shutdown: broadcast::Receiver<()>,
    _shutdown_complete: mpsc::Sender<()>,
) -> anyhow::Result<()> {
    info!("Enter loop");
    loop {
        tokio::select! {
            res = conn.recv_dgram_ready() => {
                let _ = res.map_err(|e| anyhow!(e))
                    .context("check dgram's readness")?;
                let buf = conn.recv_dgram().await
                    .map_err(|e| anyhow!(e))
                    .context("recv_dgram()")?;
                conn.send_dgram(&buf, 0).await
                    .map_err(|e| anyhow!(e))
                    .context("send_dgram")?;
            },
            _ = notify_shutdown.recv() => {
                println!("Shutdown requested");
                break;
            }
        }
    }
    info!("Leave loop");
    Ok(())
}
