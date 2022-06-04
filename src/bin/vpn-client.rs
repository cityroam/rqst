use flexi_logger::{detailed_format, FileSpec, Logger, WriteMode};
use log::{error, info};
use rqst::quic::*;
use rqst::vpn;
use std::env;
use tokio::sync::{broadcast, mpsc};

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let matches = clap::command!()
        .propagate_version(true)
        .subcommand_required(false)
        .arg_required_else_help(false)
        .arg(clap::arg!(<URL>).help("Url to connect").required(true))
        .arg(clap::arg!(-d - -disable_verify).help("Disable to verify the server certificate"))
        .arg(clap::arg!(-v - -verbose).help("Print logs to Stderr"))
        .arg(clap::arg!(-p - -pktlog).help("Write packets to a pcap file"))
        .get_matches();

    let current_exe = std::env::current_exe().unwrap();
    let logger = Logger::try_with_env_or_str("info")?
        .write_mode(WriteMode::BufferAndFlush)
        .format(detailed_format);
    let logger = if matches.is_present("verbose") {
        logger.log_to_stderr()
    } else {
        logger.log_to_file(FileSpec::default().directory(current_exe.parent().unwrap()))
    };
    let _logger_handle = logger.start()?;

    let enable_pktlog = matches.is_present("pktlog");

    let url = matches.value_of("URL").unwrap();
    let url = url::Url::parse(url).unwrap();

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    if matches.is_present("disable_verify") {
        config.verify_peer(false);
    } else {
        let ca_crt_path = std::env::current_exe().unwrap().with_file_name("ca.crt");
        config
            .load_verify_locations_from_file(ca_crt_path.to_str().unwrap())
            .unwrap();
        config.verify_peer(true);
    }

    let crt_path = std::env::current_exe()
        .unwrap()
        .with_file_name("client.crt");
    let key_path = std::env::current_exe()
        .unwrap()
        .with_file_name("client.key");
    config
        .load_cert_chain_from_pem_file(crt_path.to_str().unwrap())
        .unwrap();
    config
        .load_priv_key_from_pem_file(key_path.to_str().unwrap())
        .unwrap();

    config.set_application_protos(b"\x03vpn").unwrap();

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

    if let Some(keylog_path) = env::var_os("SSLKEYLOGFILE") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(keylog_path)
            .unwrap();
        keylog = Some(file);
        config.log_keys();
    }

    let cpus = num_cpus::get();
    info!("logical cores: {}", cpus);

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
    socket.set_only_v6(true).unwrap();
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

    let mut notify_shutdown_rx = notify_shutdown.subscribe();
    let notify_shutdown_rx1 = notify_shutdown.subscribe();
    let shutdown_complete_tx1 = shutdown_complete_tx.clone();

    let task = tokio::spawn(async move {
        let shutdown_complete_tx1 = shutdown_complete_tx1;

        info!("connecting to {}", &url);
        let conn = tokio::select! {
            ret = quic.connect(url) => {
                match ret {
                    Ok(conn) => {
                        info!(
                            "Connection connected: {:?}",
                            quiche::ConnectionId::from_vec(conn.conn_id.clone())
                        );
                        conn
                   },
                   Err(e) => {
                       error!("connect failed: {:?}", e);
                       return;
                   }
                }
            },
            _ = notify_shutdown_rx.recv() => {
                info!("connect canceled!");
                return;
            },
        };

        vpn::transfer(
            conn,
            notify_shutdown_rx,
            notify_shutdown_rx1,
            shutdown_complete_tx1,
            enable_pktlog,
            false,
        )
        .await;
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
