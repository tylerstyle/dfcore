//! Shared forensic safety core for the dfnix tools.
//!
//! - [`lsblk`]: block device tree as reported by `lsblk -J`, with system-device detection
//! - [`sysfs`]: which physical disks a device or a path is ultimately stored on
//! - [`protected`]: registry of devices that must never be written (`/run/dfnix/protected.json`)
//! - [`audit`]: append-only, SHA-256 hash-chained JSONL audit log
//! - [`release`]: the dfnix system revision a tool runs on
//! - [`Refusal`]: the error type of every policy decision that refuses an operation

pub mod audit;
pub mod host;
pub mod lsblk;
pub mod protected;
pub mod refusal;
pub mod release;
pub mod sysfs;

pub use refusal::{is_refusal, Refusal};
