use anyhow::{anyhow, Context};
use flexi_logger::{detailed_format, FileSpec, Logger, WriteMode};
use log::{error, info};
#[cfg(windows)]
use once_cell::sync::Lazy;
use rqst::quic::*;
use rqst::vpn::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
#[cfg(windows)]
use std::sync::Mutex;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use std::collections::HashMap;

#[cfg(windows)]
static MATCHES: Lazy<Mutex<Option<clap::ArgMatches>>> = Lazy::new(|| Mutex::new(None));

fn main() -> anyhow::Result<()> {
    let cert_default_path = std::env::current_exe()
        .unwrap()
        .with_file_name("server.crt");
    let key_default_path = std::env::current_exe()
        .unwrap()
        .with_file_name("server.key");
    let ca_default_path = std::env::current_exe().unwrap().with_file_name("ca.crt");

    let log_default_path = FileSpec::default()
        .directory(std::env::current_exe().unwrap().parent().unwrap())
        .as_pathbuf(None);

    let app = clap::command!()
        .propagate_version(true)
        .subcommand_required(false)
        .arg_required_else_help(false)
        .arg(clap::arg!(-d - -disable_verify).help("Disable to verify the client certificate"))
        .arg(clap::arg!(-v - -verbose).help("Print logs to Stderr"))
        .arg(clap::arg!(-p - -pktlog).help("Write packets to a pcap file"))
        .arg(
            clap::arg!(--cert <file>)
                .required(false)
                .value_parser(clap::value_parser!(PathBuf))
                .default_value(cert_default_path.to_str().unwrap())
                .help("TLS certificate path"),
        )
        .arg(
            clap::arg!(--key <file>)
                .required(false)
                .value_parser(clap::value_parser!(PathBuf))
                .default_value(key_default_path.to_str().unwrap())
                .help("TLS key path"),
        )
        .arg(
            clap::arg!(--ca <file>)
                .required(false)
                .value_parser(clap::value_parser!(PathBuf))
                .default_value(ca_default_path.to_str().unwrap())
                .help("CA certificate path"),
        )
        .arg(
            clap::arg!(--port <PORT>)
                .required(false)
                .value_parser(clap::value_parser!(u16))
                .default_value("4433")
                .help("Listening UDP port"),
        )
        .arg(
            clap::arg!(--log <file>)
                .required(false)
                .value_parser(clap::value_parser!(PathBuf))
                .default_value(log_default_path.to_str().unwrap())
                .help("log path"),
        );

    #[cfg(windows)]
    let app = app
        .subcommand(clap::Command::new("install").about("Install this program as service"))
        .subcommand(clap::Command::new("uninstall").about("Uninstall this program as service"))
        .subcommand(
            clap::Command::new("run_as_service").about("Work as service (Not used manually!)"),
        );
    let matches = app.get_matches();

    let mut log_path = std::env::current_dir().unwrap();
    log_path.push(
        matches
            .get_one::<PathBuf>("log")
            .ok_or(anyhow!("log not provided"))?,
    );

    let logger = Logger::try_with_env_or_str("info")?
        .write_mode(WriteMode::BufferAndFlush)
        .format(detailed_format);
    let logger = if matches.is_present("verbose") {
        logger.log_to_stderr()
    } else {
        logger.log_to_file(FileSpec::try_from(log_path)?)
    };
    let _logger_handle = logger.start()?;

    match matches.subcommand() {
        #[cfg(windows)]
        Some(("install", _)) => {
            if let Err(e) = vpn_server_service::install() {
                eprintln!("{:?}", e);
            }
        }
        #[cfg(windows)]
        Some(("uninstall", _)) => {
            if let Err(e) = vpn_server_service::uninstall() {
                eprintln!("{:?}", e);
            }
        }
        #[cfg(windows)]
        Some(("run_as_service", _)) => {
            MATCHES.lock().unwrap().replace(matches);
            if let Err(e) = vpn_server_service::run() {
                eprintln!("{:?}", e);
            }
        }
        None => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                if let Err(e) = tokio_main(None, &matches).await {
                    error!("{:?}", e);
                };
            }),
        _ => {}
    }
    Ok(())
}

#[cfg(windows)]
mod vpn_server_service {
    use std::env;
    use std::ffi::OsString;
    use std::thread::sleep;
    use std::time::Duration;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl,
            ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    const SERVICE_NAME: &str = "quic_vpn_server";
    const SERVICE_DISPLAY_NAME: &str = "QUIC VPN Server";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    pub fn install() -> windows_service::Result<()> {
        let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
        let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
        let service_binary_path = env::current_exe().unwrap().with_file_name("vpn-server.exe");

        let service_info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(SERVICE_DISPLAY_NAME),
            service_type: SERVICE_TYPE,
            start_type: ServiceStartType::OnDemand,
            error_control: ServiceErrorControl::Normal,
            executable_path: service_binary_path,
            launch_arguments: vec![OsString::from("run_as_service")],
            dependencies: vec![],
            account_name: None, // run as System
            account_password: None,
        };
        let service =
            service_manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;
        service.set_description("QUIC VPN Server")?;
        Ok(())
    }

    pub fn uninstall() -> windows_service::Result<()> {
        let manager_access = ServiceManagerAccess::CONNECT;
        let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
        let service_access =
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;

        let service = service_manager.open_service(SERVICE_NAME, service_access)?;

        let service_status = service.query_status()?;
        if service_status.current_state != ServiceState::Stopped {
            service.stop()?;
            // Wait for service to stop
            sleep(Duration::from_secs(1));
        }

        service.delete()?;
        Ok(())
    }

    pub fn run() -> windows_service::Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    define_windows_service!(ffi_service_main, my_service_main);

    fn my_service_main(_arguments: Vec<OsString>) {
        if let Err(_e) = run_service() {}
    }

    fn run_service() -> windows_service::Result<()> {
        let (notify_stop_tx, notify_stop_rx) = tokio::sync::mpsc::channel::<()>(1);

        let status_handle = service_control_handler::register(
            SERVICE_NAME,
            move |control_event| -> ServiceControlHandlerResult {
                match control_event {
                    ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                    ServiceControl::Stop => {
                        let _ = notify_stop_tx.try_send(());
                        ServiceControlHandlerResult::NoError
                    }
                    _ => ServiceControlHandlerResult::NotImplemented,
                }
            },
        )?;

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        let matches = crate::MATCHES
            .lock()
            .unwrap()
            .take()
            .expect("MATCHES not set");

        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let _ = crate::tokio_main(Some(notify_stop_rx), &matches).await;
            });

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;
        Ok(())
    }
}

async fn tokio_main(
    notify_stop: Option<mpsc::Receiver<()>>,
    matches: &clap::ArgMatches,
) -> anyhow::Result<()> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    if !matches.is_present("disable_verify") {
        config
            .load_verify_locations_from_file(
                matches
                    .get_one::<PathBuf>("ca")
                    .ok_or(anyhow!("ca's path not provided"))?
                    .to_str()
                    .ok_or(anyhow!("ca's path includes non-UTF-8"))?,
            )
            .context("load CA cert file")?;
        config.verify_peer(true);
    }

    config
        .load_cert_chain_from_pem_file(
            matches
                .get_one::<PathBuf>("cert")
                .ok_or(anyhow!("cert's path not provided"))?
                .to_str()
                .ok_or(anyhow!("cert's path includes non-UTF-8"))?,
        )
        .context("load cert file")?;
    config
        .load_priv_key_from_pem_file(
            matches
                .get_one::<PathBuf>("key")
                .ok_or(anyhow!("key's path not provided"))?
                .to_str()
                .ok_or(anyhow!("key's path includes non-UTF-8"))?,
        )
        .context("load key file")?;

    config.set_application_protos(&[b"vpn"])?;

    config.set_max_idle_timeout(0);
    config.set_max_recv_udp_payload_size(1350);
    config.set_max_send_udp_payload_size(1350);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_active_connection_id_limit(12);
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
    let (mut notify_stop, work_as_service) = if let Some(notify_stop) = notify_stop {
        (notify_stop, true)
    } else {
        let (_, notify_stop) = mpsc::channel(1);
        (notify_stop, false)
    };

    let quic = QuicHandle::new(
        config,
        keylog,
        quiche::MAX_CONN_ID_LEN,
        !matches.is_present("disable_verify"),
        shutdown_complete_tx.clone(),
    );

    let local = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        matches
            .get_one::<u16>("port")
            .cloned()
            .ok_or(anyhow!("port not provided"))?,
    );
    quic.listen(local).await.unwrap();
    let local = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        matches
            .get_one::<u16>("port")
            .cloned()
            .ok_or(anyhow!("port not provided"))?,
    );
    quic.listen(local).await.unwrap();

    loop {
        tokio::select! {
            Ok(conn) = quic.accept() => {
                info!("Connection accepted: {}", conn.conn_handle);
                tokio::spawn(process_client(
                    conn,
                    notify_shutdown.subscribe(),
                    shutdown_complete_tx.clone(),
                    matches.is_present("pktlog"),
                    )
                );
            }
            _ = tokio::signal::ctrl_c(), if !work_as_service => {
                drop(notify_shutdown);
                break;
            }
            _ = notify_stop.recv(), if work_as_service => {
                drop(notify_shutdown);
                break;
            }
        }
    }
    drop(quic);
    drop(shutdown_complete_tx);
    let _ = shutdown_complete_rx.recv().await;
    Ok(())
}

async fn process_client(
    conn: QuicConnectionHandle,
    mut notify_shutdown_rx: broadcast::Receiver<()>,
    shutdown_complete_tx: mpsc::Sender<()>,
    enable_pktlog: bool,
) -> anyhow::Result<()> {
    let mut ctrlmng = ControlManager::new(true);
    let mut tunnelmng = TunnelManager::new(conn.clone(), HashMap::new());
    let (notify_tunnel_tx, _) = broadcast::channel::<HashMap<u8, u64>>(100);
    let mut notify_shutdown_vpn = None;
    let mut running_vpn = false;
    let mut set = JoinSet::new();

    info!("Enter loop for client");
    loop {
        tokio::select! {
            res = conn.recv_stream_ready(None, Some((true, false, false, false))) => {
                let readable = res.map_err(|e| anyhow!(e))
                    .context("check stream's readness")?;
                for stream_id in readable {
                    match ctrlmng.recv_request(&conn, stream_id).await
                        .with_context(|| format!("receive and parse request in {} stream", stream_id))?
                    {
                        Some((seq, RequestMsg::Start)) => {
                            info!("Recv start request");
                            let (notify_shutdown_tx, _) = broadcast::channel(1);
                            set.spawn(transfer(
                                conn.clone(),
                                notify_shutdown_tx.subscribe(),
                                notify_shutdown_tx.subscribe(),
                                notify_tunnel_tx.subscribe(),
                                notify_tunnel_tx.subscribe(),
                                shutdown_complete_tx.clone(),
                                enable_pktlog,
                                false,
                                )
                            );
                            notify_shutdown_vpn = Some(notify_shutdown_tx);
                            running_vpn = true;
                            ctrlmng.send_response_ok(&conn, seq).await
                                .context("send response ok for start")?;

                            let available = tunnelmng
                                .available()
                                .await
                                .context("get available tunnels")?;
                            notify_tunnel_tx.send(available)
                                .context("notify tunnel")?;
                        }
                        Some((seq, RequestMsg::Stop)) => {
                            info!("Recv stop request");
                            if let Some(notify) = notify_shutdown_vpn.take() {
                                drop(notify);
                                running_vpn = false;
                                ctrlmng.send_response_ok(&conn, seq).await
                                    .context("send response ok for stop")?;
                            } else {
                                ctrlmng.send_response_err(&conn, seq, "not running").await
                                    .context("send response err for stop")?;
                            }
                        }
                        Some((seq, RequestMsg::Tunnel(TunnelMsg { dscp, group_id }))) => {
                            info!("Recv tunnel request");
                            tunnelmng.insert(dscp, group_id);
                            ctrlmng.send_response_ok(&conn, seq).await
                                .context("send response ok for tunnel")?;
                        }

                        msg => {
                            info!("Recv unknown request: {:?}", msg);
                        }
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
                        if running_vpn {
                            let available = tunnelmng
                                .available()
                                .await
                                .context("get available tunnels")?;
                            notify_tunnel_tx.send(available)
                                .context("notify tunnel")?;
                        }
                    },

                    quiche::PathEvent::RemoveGroup(..) => unreachable!(),
                }
            },
            res = set.join_next(), if !set.is_empty() => {
                if let Some(res) = res {
                    if let Err(e) = res? {
                        error!("Error occured in spawned task: {:?}", e);
                    }
                }
            }
            _ = notify_shutdown_rx.recv() => {
                info!("Shutdown requested");
                drop(notify_shutdown_vpn);
                while let Some(res) = set.join_next().await {
                    if let Err(e) = res? {
                        error!("Error occured in spawned task: {:?}", e);
                    }
                }
                break;
            }

        }
    }
    info!("Leave loop for client");
    Ok(())
}