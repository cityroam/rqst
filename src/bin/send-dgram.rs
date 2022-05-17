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

    config
        .load_verify_locations_from_file("src/ca.crt")
        .unwrap();
    config.verify_peer(true);

    config
        .load_cert_chain_from_pem_file("src/client.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("src/client.key")
        .unwrap();

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

    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    let address: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
    let address = address.into();
    socket.bind(&address)?;
    socket.set_recv_buffer_size(0x7fffffff).unwrap();
    socket.set_nonblocking(true).unwrap();
    let udp: std::net::UdpSocket = socket.into();
    let udp = tokio::net::UdpSocket::from_std(udp).unwrap();

    let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?;
    let address: std::net::SocketAddr = "[::]:0".parse().unwrap();
    let address = address.into();
    socket.bind(&address)?;
    socket.set_recv_buffer_size(0x7fffffff).unwrap();
    socket.set_nonblocking(true).unwrap();
    let udp6: std::net::UdpSocket = socket.into();
    let udp6 = tokio::net::UdpSocket::from_std(udp6).unwrap();

    let quic = QuicHandle::new(
        udp,
        udp6,
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
        let conn = tokio::select! {
            ret = quic.connect(url) => {
                match ret {
                    Ok(conn) => {
                        println!(
                            "Connection established: {:?}",
                            quiche::ConnectionId::from_vec(conn.conn_id.clone())
                        );
                        conn
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
                /*
                _ = sleep(Duration::from_nanos(0)) => {
                    let res = quic.send_dgram(conn_id.clone(), &buf).await;
                */
                res = conn.send_dgram(&buf) => {
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
