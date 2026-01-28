// Проверка синтаксиса основных изменений
use clap::{Parser, Subcommand};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    #[cfg(unix)]
    InstallService {
        service_name: String,
        install_dir: String,
        service_user: String,
    },
}

#[cfg(unix)]
fn install_linux_service(
    service_name: &str,
    install_dir: &str,
    service_user: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Installing service: {} in {} for user {}", service_name, install_dir, service_user);
    Ok(())
}

fn main() {
    println!("Syntax check passed!");
}
