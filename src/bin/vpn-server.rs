use flexi_logger::{detailed_format, FileSpec, Logger, WriteMode};
use log::info;
use rqst::quic::*;
use rqst::vpn;
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, mpsc};

fn main() {
    let matches = clap::command!()
        .propagate_version(true)
        .subcommand_required(false)
        .arg_required_else_help(false)
        .arg(clap::arg!(-d - -disable_verify).help("Disable to verify the client certificate"))
        .arg(clap::arg!(-v - -verbose).help("Print logs to Stderr"))
        .subcommand(clap::Command::new("install").about("Install this program as service"))
        .subcommand(clap::Command::new("uninstall").about("Uninstall this program as service"))
        .subcommand(
            clap::Command::new("run_as_service").about("Work as service (Not used manually!)"),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("install", _)) => {
            if let Err(e) = vpn_server_service::install() {
                eprintln!("{:?}", e);
            }
        }
        Some(("uninstall", _)) => {
            if let Err(e) = vpn_server_service::uninstall() {
                eprintln!("{:?}", e);
            }
        }
        Some(("run_as_service", _)) => {
            if let Err(e) = vpn_server_service::run() {
                eprintln!("{:?}", e);
            }
        }
        None => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let _ = tokio_main(
                    None,
                    matches.is_present("disable_verify"),
                    matches.is_present("verbose"),
                )
                .await;
            }),
        _ => {}
    }
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

        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let _ = crate::tokio_main(Some(notify_stop_rx), false, false).await;
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
    disable_verify: bool,
    verbose: bool,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let current_exe = std::env::current_exe().unwrap();
    let logger = Logger::try_with_env_or_str("info")?
        .write_mode(WriteMode::BufferAndFlush)
        .format(detailed_format);
    let logger = if verbose {
        logger.log_to_stderr()
    } else {
        logger.log_to_file(FileSpec::default().directory(current_exe.parent().unwrap()))
    };
    let _logger_handle = logger.start()?;

    let tap_entries = vpn::get_tap_entries()?;
    if tap_entries.is_empty() {
        panic!("No tap interface");
    }

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    if !disable_verify {
        let ca_crt_path = std::env::current_exe().unwrap().with_file_name("ca.crt");
        config
            .load_verify_locations_from_file(ca_crt_path.to_str().unwrap())
            .unwrap();
        config.verify_peer(true);
    }

    let crt_path = std::env::current_exe()
        .unwrap()
        .with_file_name("server.crt");
    let key_path = std::env::current_exe()
        .unwrap()
        .with_file_name("server.key");
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

    if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
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
    let (mut notify_stop, work_as_service) = if let Some(notify_stop) = notify_stop {
        (notify_stop, true)
    } else {
        let (_, notify_stop) = mpsc::channel(1);
        (notify_stop, false)
    };

    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    let address: std::net::SocketAddr = "0.0.0.0:3456".parse().unwrap();
    let address = address.into();
    socket.bind(&address)?;
    socket.set_recv_buffer_size(0x7fffffff).unwrap();
    socket.set_nonblocking(true).unwrap();
    let udp: std::net::UdpSocket = socket.into();
    let udp = tokio::net::UdpSocket::from_std(udp).unwrap();

    let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?;
    let address: std::net::SocketAddr = "[::]:3456".parse().unwrap();
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
        !disable_verify,
        shutdown_complete_tx.clone(),
    );
    let tap_entries = Arc::new(Mutex::new(tap_entries));
    loop {
        tokio::select! {
            Ok(conn) = quic.accept() => {
                info!(
                    "Connection accepted: {:?}",
                    quiche::ConnectionId::from_vec(conn.conn_id.clone())
                );
                tokio::spawn(vpn::transfer(
                    conn,
                    tap_entries.clone(),
                    notify_shutdown.subscribe(),
                    notify_shutdown.subscribe(),
                    shutdown_complete_tx.clone(),
                    false,
                    false,
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
