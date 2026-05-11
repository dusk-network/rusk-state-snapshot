mod archive;
mod archive_blob;
mod cli;
mod commands;
mod config;
mod errors;
mod hashing;
mod journal;
mod manifest;
mod object_store;
mod planner;
mod pointer;
mod retention;
mod safe_extract;
mod signing;
mod tip;

use anyhow::Result;
use clap::Parser;

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    commands::run(cli).await
}
