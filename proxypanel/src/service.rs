use crate::app::{self, AppConfig};
use anyhow::{anyhow, Result};
use std::{
    ffi::OsString,
    sync::OnceLock,
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

struct ServiceRuntime {
    service_name: String,
    config: AppConfig,
}

static SERVICE_RUNTIME: OnceLock<ServiceRuntime> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

pub fn run_service(service_name: String, config: AppConfig) -> Result<()> {
    SERVICE_RUNTIME
        .set(ServiceRuntime {
            service_name: service_name.clone(),
            config,
        })
        .map_err(|_| anyhow!("Service runtime already initialized"))?;

    service_dispatcher::start(service_name, ffi_service_main)
    .map_err(|err| anyhow!("Failed to start service dispatcher: {}", err))?;

    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    let runtime = match SERVICE_RUNTIME.get() {
        Some(runtime) => runtime,
        None => {
            error!("Service runtime not initialized");
            return;
        }
    };
    if let Err(err) = service_main_inner(runtime) {
        error!("Service error: {}", err);
    }
}

fn service_main_inner(runtime: &ServiceRuntime) -> Result<()> {
    let shutdown = CancellationToken::new();
    let shutdown_signal = shutdown.clone();

    let status_handle = service_control_handler::register(
        runtime.service_name.clone(),
        move |control_event| match control_event {
            ServiceControl::Stop => {
                shutdown_signal.cancel();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        },
    )?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(2),
        process_id: None,
    })?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(0),
        process_id: None,
    })?;

    let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let result = tokio_runtime.block_on(app::run_app(runtime.config.clone(), shutdown));

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(0),
        process_id: None,
    })?;

    result
}

pub fn install_service(service_name: String, http_addr: &str, data_dir: &str) -> Result<()> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;
    let exe_path = std::env::current_exe()?;

    let launch_arguments = vec![
        OsString::from("--http-addr"),
        OsString::from(http_addr),
        OsString::from("--data-dir"),
        OsString::from(data_dir),
        OsString::from("service"),
        OsString::from("--service-name"),
        OsString::from(service_name.clone()),
    ];

    let service_info = ServiceInfo {
        name: service_name.clone().into(),
        display_name: service_name.clone().into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path,
        launch_arguments,
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    let service = manager.create_service(&service_info, ServiceAccess::START)?;
    let no_args: [&str; 0] = [];
    service.start(&no_args)?;
    info!("Service installed and started: {}", service_name);
    Ok(())
}

pub fn uninstall_service(service_name: String) -> Result<()> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        service_name.clone(),
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    )?;

    let _ = service.stop();
    service.delete()?;
    info!("Service removed: {}", service_name);
    Ok(())
}
