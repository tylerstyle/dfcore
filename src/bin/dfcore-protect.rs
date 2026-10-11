//! Write the protected-device registry: run once at boot, before evidence is attached
//! or handled. `dfcore-protect [--output PATH] [--print]`

use anyhow::{bail, Result};
use dfcore::{lsblk, protected};
use std::path::PathBuf;

fn main() -> Result<()> {
    let mut output = protected::path();
    let mut print = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output" => match args.next() {
                Some(p) => output = PathBuf::from(p),
                None => bail!("--output needs a path"),
            },
            "--print" => print = true,
            "-h" | "--help" => {
                println!("Usage: dfcore-protect [--output PATH] [--print]");
                return Ok(());
            }
            other => bail!("Unknown argument: {other}"),
        }
    }
    let registry = protected::Registry::build(&lsblk::scan()?);
    if print {
        println!("{}", serde_json::to_string_pretty(&registry)?);
    }
    registry.write_atomic(&output)?;
    // Start each boot's chain with what was protected, before any tool runs
    let devices: Vec<serde_json::Value> = registry
        .devices
        .iter()
        .map(
            |d| serde_json::json!({ "role": d.role, "identity": d.identity, "reasons": d.reasons }),
        )
        .collect();
    let event = dfcore::audit::Event::new(
        "dfcore-protect",
        env!("CARGO_PKG_VERSION"),
        "protected_registry",
    )
    .detail("registry", output.to_string_lossy().to_string())
    .detail("devices", devices);
    if let Err(e) = dfcore::audit::append(event) {
        eprintln!("[dfcore] WARNING: audit log not written: {e:#}");
    }
    for d in &registry.devices {
        eprintln!(
            "[dfcore] protected {:?}: {} ({})",
            d.role,
            d.identity.path,
            d.identity.serial.as_deref().unwrap_or("no serial")
        );
    }
    eprintln!("[dfcore] registry written to {}", output.display());
    Ok(())
}
