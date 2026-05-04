mod archive;
mod cli;
mod commands;
mod config;
mod errors;
mod hashing;
mod manifest;
mod object_store;
mod pointer;
mod retention;
mod safe_extract;
mod signing;

use anyhow::Result;
use clap::Parser;

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    commands::run(cli).await
}
