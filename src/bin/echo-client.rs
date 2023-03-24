extern crate env_logger;

use anyhow::{anyhow, Context};
use bytes::{BytesMut, BufMut};
use log::{info, error};
use rqst::{quic::*, vpn::*};
use std::env;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, LinesCodec};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    let (shutdown_complete_tx, mut shutdown_complete_rx) = mpsc::channel(1);

    let quic = QuicHandle::new(
        config,
        keylog,
        quiche::MAX_CONN_ID_LEN,
        false,
        shutdown_complete_tx,
    );

    info!("Connecting to {}", &url);
    let conn = quic.connect(url, None).await.map_err(|e| anyhow!(e)).context("connect()")?;
    tokio::select! {
        res = conn.wait_connected() => {
            res.map_err(|e| anyhow!(e)).context("wait_connected()")?;
            info!("Connection established: {}", conn.conn_handle);
        },
        _ = tokio::signal::ctrl_c() => {
            info!("Control C signaled");
            drop(quic);
            let _ = shutdown_complete_rx.recv().await;
            return Ok(());
        }
    };

    if let Ok(paths) = conn.path_stats().await {
        assert_eq!(paths.len(), 1);
        let mut local_addr = paths[0].local_addr;
        let peer_addr = paths[0].peer_addr;

        conn.insert_group(local_addr, peer_addr, 1).await.ok();

        local_addr.set_port(local_addr.port() + 1);
        match conn.probe_path(local_addr, peer_addr).await {
            Ok(_) => {
                info!("Request probing ({} {})", local_addr, peer_addr);
            }
            Err(e) => {
                info!("failed to probe_path: {:?}", e);
            }
        }
    }

    let mut echo_service_running = false;
    let mut ctrlmng = ControlManager::new(false);

    info!("Enter loop");
    let mut now = Instant::now();

    let mut stdin_reader = FramedRead::new(tokio::io::stdin(), LinesCodec::new());

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

        tokio::select! {
            res = stdin_reader.next() => {
                if let Some(line) = res.transpose().map_err(|e| anyhow!(e))
                    .context("read from stdin")?
                {
                    if line.is_empty() {
                        // Sending Start or Stop
                        if !echo_service_running {
                            info!("Sending start request");
                            let seq = ctrlmng.send_start_request(&conn).await?;
                            match ctrlmng.recv_response(&conn, seq).await
                                .context("recv response")?
                            {
                                ResponseMsg::Ok => {
                                    info!("Echo service running");
                                    echo_service_running = true;
                                }
                                ResponseMsg::Err(reason) => {
                                    error!("Cannot start Echo service: {}", reason);
                                }
                            }
                        } else {
                            let seq = ctrlmng.send_stop_request(&conn).await?;
                            match ctrlmng.recv_response(&conn, seq).await
                                .context("recv response")?
                            {
                                ResponseMsg::Ok => {
                                    info!("Echo service stopped");
                                    echo_service_running = false;
                                }
                                ResponseMsg::Err(reason) => {
                                    error!("Cannot stop Echo service: {}", reason);
                                }
                            }
                        }
                    } else {
                        if echo_service_running {
                            let mut buf = BytesMut::new();
                            buf.put(line.as_bytes());
                            conn.send_dgram(&buf.freeze(), 0).await
                                .map_err(|e| anyhow!(e))
                                .context("send_dgram()")?;
                            let echoed = conn.recv_dgram().await
                                .map_err(|e| anyhow!(e))
                                .context("recv_dgram()")?;
                            println!("echoed: {}",  std::str::from_utf8(&echoed[..])?);
                        } else {
                            error!("Echo service not running");
                        }
                    }
                }
            }
            res = conn.recv_stream_ready(None, Some((false, true, false, false))) => {
                // Only check readness of Server -> Client Bi
                let readable = res.map_err(|e| anyhow!(e))
                    .context("check stream's readness")?;
                for stream_id in readable {
                    match ctrlmng.recv_request(&conn, stream_id).await.with_context(|| format!("receive and parse request in {} stream", stream_id))? {
                        _ => {}
                    }
                }
            }
            res = conn.path_event() => {
                let event = res.map_err(|e| anyhow!(e))
                    .context("path_event()")?;
                match event {
                    quiche::PathEvent::New(..) => unreachable!(),

                    quiche::PathEvent::Validated(local_addr, peer_addr) => {
                        info!("Path ({}, {}) is now validated", local_addr, peer_addr);
                        conn.set_active(local_addr, peer_addr, true).await.ok();
                    }

                    quiche::PathEvent::ReturnAvailable(local_addr, peer_addr) => {
                        info!("Path ({}, {})'s return is now available", local_addr, peer_addr);
                        conn.insert_group(local_addr, peer_addr, 2).await.ok();
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

                    quiche::PathEvent::PeerMigrated(..) => unreachable!(),

                    quiche::PathEvent::PeerPathStatus(..) => {},

                    quiche::PathEvent::InsertGroup(..) => unreachable!(),

                    quiche::PathEvent::RemoveGroup(..) => unreachable!(),
                }
            },
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl-C signaled");
                if echo_service_running {
                    ctrlmng.send_stop_request(&conn).await
                        .context("sending stop request after Ctrl-C")?;
                }
                break;
            }
    
        }
    }
    info!("Leave loop");
    conn.close().await.unwrap();
    drop(conn);
    drop(quic);
    let _ = shutdown_complete_rx.recv().await;
    Ok(())
}
