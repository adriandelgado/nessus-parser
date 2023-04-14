use clap::{Parser, Subcommand};
use std::{net::IpAddr, path::PathBuf};

/// Program to parse `.nessus` info
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(
    help_template = "{before-help}{about-with-newline}\n{usage-heading} {usage}\n\n{all-args}{after-help}\n\n{author-with-newline}"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    List {
        /// Input file to parse or directory with '.nessus' files
        input: PathBuf,

        /// Only show IPs with an exploit available
        #[arg(short = 'x', long)]
        exploitable: bool,
    },
    Summary {
        /// Input file to parse or directory with '.nessus' files
        input: PathBuf,

        /// Host to summarize
        host: IpAddr,
    },
}
