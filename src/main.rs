use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::EnvFilter;

use dhcplease::{Config, DhcpServer, Result};

#[derive(Parser)]
#[command(name = "dhcplease")]
#[command(author, version, about = "A developer-grade DHCP server", long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "config.json")]
    config: PathBuf,

    #[arg(short, long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Run,
    ShowConfig,
    ListLeases,
    CleanupLeases,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
        )
        .init();

    let config = Config::load_or_create(&cli.config).await?;

    match cli.command.unwrap_or(Commands::Run) {
        Commands::Run => {
            info!("Starting DHCP server with config: {:?}", cli.config);
            let server = DhcpServer::new(config).await?;

            tokio::select! {
                result = server.run() => result,
                _ = tokio::signal::ctrl_c() => {
                    info!("Received shutdown signal, stopping server...");
                    if let Err(error) = server.save_leases().await {
                        tracing::error!("Failed to save leases on shutdown: {}", error);
                    }
                    Ok(())
                }
            }
        }
        Commands::ShowConfig => {
            println!("{}", serde_json::to_string_pretty(&config)?);
            Ok(())
        }
        Commands::ListLeases => {
            let store = dhcplease::Leases::new(Arc::new(config)).await?;
            let leases = store.list_leases().await;

            if leases.is_empty() {
                println!("No active leases.");
            } else {
                println!(
                    "{:<24} {:<16} {:<24} {:<10}",
                    "Client ID", "IP Address", "Expires At", "Remaining"
                );
                println!("{}", "-".repeat(76));

                for lease in leases {
                    let remaining = lease.remaining_seconds();
                    let remaining_str = if remaining > 0 {
                        format!("{}s", remaining)
                    } else {
                        "expired".to_string()
                    };

                    println!(
                        "{:<24} {:<16} {:<24} {:<10}",
                        lease.client_id,
                        lease.ip_address,
                        lease.expires_at.format("%Y-%m-%d %H:%M:%S UTC"),
                        remaining_str
                    );
                }
            }

            Ok(())
        }
        Commands::CleanupLeases => {
            let store = dhcplease::Leases::new(Arc::new(config)).await?;
            let count = store.cleanup_expired_leases().await?;
            println!("Cleaned up {} expired lease(s).", count);
            Ok(())
        }
    }
}
