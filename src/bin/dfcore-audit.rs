//! Inspect the dfnix audit log.
//!
//!   dfcore-audit verify [LOG]        check the whole chain; exit 1 if it is broken
//!   dfcore-audit head [LOG]          print the chain head (hash of the last record)
//!   dfcore-audit export DIR [LOG]    copy the log and its head into a case directory
//!                                    (audit-<boot_id>.jsonl / .head; never overwrites
//!                                    another boot's copy)

use anyhow::{bail, Result};
use dfcore::audit;
use std::path::PathBuf;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let log = |i: usize| args.get(i).map(PathBuf::from).unwrap_or_else(audit::path);
    match args.first().map(String::as_str) {
        Some("verify") => {
            let state = audit::verify(&log(1))?;
            println!("OK: {} records, head {}", state.records, state.head);
        }
        Some("head") => println!("{}", audit::verify(&log(1))?.head),
        Some("export") => {
            let Some(dir) = args.get(1) else {
                bail!("export needs a directory");
            };
            let info = audit::export(&log(2), &PathBuf::from(dir))?;
            println!(
                "Exported {} records to {}, head {} ({})",
                info.state.records,
                info.jsonl.display(),
                info.state.head,
                info.head.display()
            );
        }
        _ => bail!("Usage: dfcore-audit verify [LOG] | head [LOG] | export DIR [LOG]"),
    }
    Ok(())
}
