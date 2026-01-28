mod app;
mod geo;
mod geo_update;
mod port_range;
mod protocol;
mod udp_proxy;
#[cfg(windows)]
mod service;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(author, version, about = "TCP proxy manager with web panel\n\nCross-platform commands:\n  install             Install as system service\n  run                 Run in console mode\n\nLinux specific:\n  uninstall-service   Uninstall systemd service\n  generate-service    Generate systemd service file\n\nExample usage:\n  proxy_panel --http-addr 0.0.0.0:1024 --data-dir /data --allowed-networks 10.250.1.0/16 install --service-name ProxyPanel\n  proxy_panel --http-addr 0.0.0.0:9090 run\n  proxy_panel generate-service > /etc/systemd/system/proxy-panel.service")]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:8080")]
    http_addr: String,
    #[arg(long, default_value = "data")]
    data_dir: String,
    #[arg(long, value_delimiter = ',', help = "Allowed IP networks (e.g., 10.250.1.0/16,192.168.1.0/24)")]
    allowed_networks: Vec<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Run,
    #[cfg(windows)]
    Service {
        #[arg(long, default_value = "ProxyPanel")]
        service_name: String,
    },
    Install {
        #[arg(long, default_value = "ProxyPanel")]
        service_name: String,
    },
    #[cfg(windows)]
    Uninstall {
        #[arg(long, default_value = "ProxyPanel")]
        service_name: String,
    },
    #[cfg(unix)]
    UninstallService {
        #[arg(long, default_value = "proxy-panel")]
        service_name: String,
    },
    #[cfg(unix)]
    GenerateSystemdService {
        #[arg(long, default_value = "proxy-panel")]
        service_name: String,
        #[arg(long, default_value = "/opt/proxy_panel")]
        install_dir: String,
        #[arg(long, default_value = "proxy")]
        service_user: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let cli = Cli::parse();
    let config = app::AppConfig::new(&cli.http_addr, &cli.data_dir, cli.allowed_networks.clone())?;

    match cli.command.unwrap_or(Command::Run) {
        Command::Run => run_console(config).await,
        #[cfg(windows)]
        Command::Service { service_name } => service::run_service(service_name, config),
        Command::Install { service_name } => {
            #[cfg(windows)]
            {
                service::install_service(service_name, &cli.http_addr, &cli.data_dir)
            }
            #[cfg(unix)]
            {
                let allowed_networks_str = if cli.allowed_networks.is_empty() {
                    String::new()
                } else {
                    format!(" --allowed-networks {}", cli.allowed_networks.join(","))
                };
                install_linux_service(
                    &service_name, 
                    "/opt/proxy_panel", 
                    "proxy", 
                    &format!("{}{}", cli.http_addr, allowed_networks_str), 
                    &cli.data_dir
                )
            }
        }
        #[cfg(windows)]
        Command::Uninstall { service_name } => service::uninstall_service(service_name),
        #[cfg(unix)]
        Command::UninstallService { service_name } => uninstall_linux_service(&service_name),
        #[cfg(unix)]
        Command::GenerateSystemdService { service_name, install_dir, service_user } => {
            generate_systemd_service(&service_name, &install_dir, &service_user, &cli.http_addr, &cli.data_dir)
        }
    }
}

async fn run_console(config: app::AppConfig) -> Result<()> {
    let shutdown = CancellationToken::new();
    let shutdown_signal = shutdown.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        shutdown_signal.cancel();
    });
    app::run_app(config, shutdown).await
}

#[cfg(unix)]
fn install_linux_service(
    service_name: &str,
    install_dir: &str,
    service_user: &str,
    http_addr_with_params: &str,
    data_dir: &str,
) -> Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    
    println!("🚀 Installing Proxy Panel as systemd service...");
    
    // Extract http_addr from parameters (strip --allowed-networks part)
    let _http_addr = if let Some(pos) = http_addr_with_params.find(" --allowed-networks") {
        &http_addr_with_params[..pos]
    } else {
        http_addr_with_params
    };
    
    // Get current executable path
    let current_exe = std::env::current_exe()?;
    let binary_path = format!("{}/proxy_panel", install_dir);
    
    // Create directories
    fs::create_dir_all(install_dir)?;
    fs::create_dir_all(&format!("{}/data", install_dir))?;
    fs::create_dir_all(&format!("{}/logs", install_dir))?;
    
    // Copy binary
    fs::copy(&current_exe, &binary_path)?;
    
    // Set permissions
    let mut perms = fs::metadata(&binary_path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&binary_path, perms)?;
    
    // Generate systemd service file
    let service_content = generate_systemd_service_content(
        service_name,
        install_dir,
        service_user,
        http_addr_with_params,
        data_dir,
    );
    
    let service_file_path = format!("/etc/systemd/system/{}.service", service_name);
    fs::write(&service_file_path, service_content)?;
    
    println!("✅ Service installed successfully!");
    println!("📋 Service file: {}", service_file_path);
    println!("🎯 Run these commands:");
    println!("   sudo systemctl daemon-reload");
    println!("   sudo systemctl enable {}", service_name);
    println!("   sudo systemctl start {}", service_name);
    
    Ok(())
}

#[cfg(unix)]
fn uninstall_linux_service(service_name: &str) -> Result<()> {
    use std::fs;
    
    println!("🗑️ Uninstalling Proxy Panel service...");
    
    let service_file_path = format!("/etc/systemd/system/{}.service", service_name);
    
    // Stop and disable service
    println!("   sudo systemctl stop {}", service_name);
    println!("   sudo systemctl disable {}", service_name);
    
    // Remove service file
    if fs::metadata(&service_file_path).is_ok() {
        fs::remove_file(&service_file_path)?;
        println!("✅ Service file removed: {}", service_file_path);
    }
    
    println!("🔄 Run: sudo systemctl daemon-reload");
    
    Ok(())
}

#[cfg(unix)]
fn generate_systemd_service(
    service_name: &str,
    install_dir: &str,
    service_user: &str,
    http_addr: &str,
    data_dir: &str,
) -> Result<()> {
    let service_content = generate_systemd_service_content(
        service_name,
        install_dir,
        service_user,
        http_addr,
        data_dir,
    );
    
    println!("📄 Systemd service content:");
    println!("{}", service_content);
    
    Ok(())
}

#[cfg(unix)]
fn generate_systemd_service_content(
    _service_name: &str,
    install_dir: &str,
    service_user: &str,
    http_addr: &str,
    data_dir: &str,
) -> String {
    format!(
        r#"[Unit]
Description=Proxy Panel Service
After=network.target

[Service]
Type=simple
User={}
Group={}
WorkingDirectory={}
ExecStart={} --http-addr {} --data-dir {}
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5

# Environment variables
Environment=RUST_LOG=info
Environment=RUST_BACKTRACE=1

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={}/data

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

# Allow binding to privileged ports
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
"#,
        service_user,
        service_user,
        install_dir,
        format!("{}/proxy_panel", install_dir),
        http_addr,
        data_dir,
        install_dir
    )
}
