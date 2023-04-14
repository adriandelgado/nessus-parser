use clap::Parser;
use color_eyre::Result;

pub mod cmd;
pub mod list;
pub mod models;
pub mod summary;
pub mod utils;

fn main() -> Result<()> {
    color_eyre::install()?;

    match cmd::Cli::parse().command {
        cmd::Commands::List { input, exploitable } => {
            if exploitable {
                list::print_ips::<true>(input)?;
            } else {
                list::print_ips::<false>(input)?;
            }
        }
        cmd::Commands::Summary { input, host } => summary::print_summary(input, host)?,
    };

    Ok(())
}
