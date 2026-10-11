//! The dfnix system revision, from `/etc/dfnix-release` (`KEY=value` lines).

use std::path::PathBuf;

pub const DEFAULT_PATH: &str = "/etc/dfnix-release";

fn path() -> PathBuf {
    std::env::var_os("DFNIX_RELEASE_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PATH))
}

pub fn parse_field(content: &str, key: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let (k, v) = line.split_once('=')?;
        (k.trim() == key)
            .then(|| v.trim().trim_matches('"').to_string())
            .filter(|v| !v.is_empty())
    })
}

/// `DFNIX_REVISION` of the running system: a git revision, `<rev>-dirty`, or `None`
/// outside dfnix.
pub fn system_revision() -> Option<String> {
    parse_field(&std::fs::read_to_string(path()).ok()?, "DFNIX_REVISION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_revision_field() {
        let content = "DFNIX_NAME=dfnix\nDFNIX_REVISION=\"57af663\"\nEMPTY=\n";
        assert_eq!(
            parse_field(content, "DFNIX_REVISION").as_deref(),
            Some("57af663")
        );
        assert_eq!(parse_field(content, "EMPTY"), None);
        assert_eq!(parse_field(content, "MISSING"), None);
    }
}
