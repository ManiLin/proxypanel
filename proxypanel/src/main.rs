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
#[command(author, version, about = "TCP proxy manager with web panel")]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:8080")]
    http_addr: String,
    #[arg(long, default_value = "data")]
    data_dir: String,
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
    #[cfg(windows)]
    Install {
        #[arg(long, default_value = "ProxyPanel")]
        service_name: String,
    },
    #[cfg(windows)]
    Uninstall {
        #[arg(long, default_value = "ProxyPanel")]
        service_name: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let cli = Cli::parse();
    let config = app::AppConfig::new(&cli.http_addr, &cli.data_dir)?;

    match cli.command.unwrap_or(Command::Run) {
        Command::Run => run_console(config).await,
        #[cfg(windows)]
        Command::Service { service_name } => service::run_service(service_name, config),
        #[cfg(windows)]
        Command::Install { service_name } => {
            service::install_service(service_name, &cli.http_addr, &cli.data_dir)
        }
        #[cfg(windows)]
        Command::Uninstall { service_name } => service::uninstall_service(service_name),
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
