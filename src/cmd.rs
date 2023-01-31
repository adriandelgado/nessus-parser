use clap::Parser;
use std::path::PathBuf;

/// Program to parse `.nessus` info
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Input file to parse or directory with '.nessus' files
    #[arg(short, long)]
    pub input: PathBuf,

    /// Write a JSON version of the file(s)
    #[arg(short = 'o', long)]
    pub json: bool,
}
