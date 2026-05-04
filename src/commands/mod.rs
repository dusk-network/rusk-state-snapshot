pub mod gc;
pub mod list;
pub mod pack;
pub mod promote;
pub mod publish;
pub mod restore;
pub mod verify;

use crate::cli::{Cli, Command};
use anyhow::Result;

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Pack(args) => pack::run(args).await,
        Command::Verify(args) => verify::run(args).await,
        Command::Publish(args) => publish::run(args).await,
        Command::Promote(args) => promote::run(args).await,
        Command::List(args) => list::run(args).await,
        Command::Restore(args) => restore::run(args).await,
        Command::Gc(args) => gc::run(args).await,
    }
}
