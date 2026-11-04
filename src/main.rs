// `async_trait` expands to functions carrying an explicit `#[must_use]` on a
// return type that is already `#[must_use]`, which trips `double_must_use`.
// The lint fires only inside macro-generated code, so allow it crate-wide.
#![allow(clippy::double_must_use)]

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
