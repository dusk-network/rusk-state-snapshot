use crate::{cli::ListArgs, config::Config, object_store};
use anyhow::Result;

pub async fn run(args: ListArgs) -> Result<()> {
    let cfg = Config::load(&args.config)?;
    let source = cfg.source(&args.source)?;
    let store = object_store::from_endpoint(source)?;
    let prefixes = match args.label.as_deref() {
        Some("latest") => vec!["v1/pointers/latest.json"],
        Some("previous") => vec!["v1/pointers/previous.json"],
        Some("daily") => vec!["v1/calendar/daily"],
        Some("monthly") => vec!["v1/calendar/monthly"],
        Some("yearly") => vec!["v1/calendar/yearly"],
        Some("pins") => vec!["v1/pins"],
        Some(other) => vec![other],
        None => vec![
            "v1/pointers",
            "v1/calendar/daily",
            "v1/calendar/monthly",
            "v1/calendar/yearly",
            "v1/pins",
            "v1/snapshots/full",
        ],
    };
    for prefix in prefixes {
        for meta in store.list_prefix(prefix).await? {
            println!("{}\t{}", meta.size, meta.path);
        }
    }
    Ok(())
}
