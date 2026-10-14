//! Policy refusals, told apart from failures by type rather than by message text.
//!
//! A [`Refusal`] is a safety rule deciding that an operation must not happen: the
//! device is protected, the image would land on the source disk, a device cannot
//! be identified well enough to tell. Everything else (I/O, parsing, a tool that
//! failed) is an ordinary error. Tools record the two differently (`refused` and
//! `error` in the audit log) and write nothing to a destination after a refusal,
//! so the distinction travels in the error chain and survives added context.

use std::fmt;

/// An operation refused by policy. Its text is the whole user-facing message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal(pub String);

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refusal {}

/// Whether `err`, or any error in its chain of causes, is a [`Refusal`].
pub fn is_refusal(err: &anyhow::Error) -> bool {
    err.chain().any(|e| e.is::<Refusal>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{anyhow, Context, Result};

    #[test]
    fn refusals_are_found_through_context() {
        let e = anyhow::Error::new(Refusal("ABORT: /dev/sda is protected".into()))
            .context("preflight")
            .context("acquisition of /dev/sda");
        assert!(is_refusal(&e));
        assert_eq!(
            format!("{e:#}"),
            "acquisition of /dev/sda: preflight: ABORT: /dev/sda is protected"
        );

        let r: Result<()> = Err(Refusal("no".into())).context("checking target");
        assert!(is_refusal(&r.unwrap_err()));
    }

    #[test]
    fn refusals_are_found_as_the_source_of_other_errors() {
        #[derive(Debug)]
        struct Wrapper(Refusal);
        impl fmt::Display for Wrapper {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("wrapped")
            }
        }
        impl std::error::Error for Wrapper {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        assert!(is_refusal(&anyhow::Error::new(Wrapper(Refusal(
            "x".into()
        )))));
    }

    #[test]
    fn ordinary_errors_are_not_refusals_whatever_they_say() {
        assert!(!is_refusal(&anyhow!(
            "Refusing to acquire: Critical Safety Error, ABORT"
        )));
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "refusing");
        assert!(!is_refusal(&anyhow::Error::new(io).context("ABORT")));
    }
}
