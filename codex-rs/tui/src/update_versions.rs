pub(crate) fn is_newer(latest: &str, current: &str) -> Option<bool> {
    match (parse_version(latest), parse_version(current)) {
        (Some(l), Some(c)) => Some(l > c),
        _ => None,
    }
}

pub(crate) fn extract_version_from_latest_tag(latest_tag_name: &str) -> anyhow::Result<String> {
    let version = latest_tag_name
        .strip_prefix("rust-v")
        .or_else(|| latest_tag_name.strip_prefix('v'))
        .ok_or_else(|| anyhow::anyhow!("Failed to parse latest tag name '{latest_tag_name}'"))?;

    Ok(version.split('-').next().unwrap_or(version).to_string())
}

pub(crate) fn is_source_build_version(version: &str) -> bool {
    parse_version(version) == Some((0, 0, 0))
}

/// Prerelease suffixes this distribution publishes on its own version line.
///
/// They mark a repackaging of the same upstream patch level, so they must
/// compare equal to the plain `MAJOR.MINOR.PATCH` release instead of being
/// rejected like an unknown prerelease. `CARGO_PKG_VERSION` carries one of
/// them, so rejecting it here would silently disable the update check.
const FORK_PRERELEASE_SUFFIXES: &[&str] = &["termux", "agentcodi"];

fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut iter = v.trim().split('.');
    let maj = iter.next()?.parse::<u64>().ok()?;
    let min = iter.next()?.parse::<u64>().ok()?;
    let pat_str = iter.next()?;
    let mut pat_parts = pat_str.splitn(2, '-');
    let pat = pat_parts.next()?.parse::<u64>().ok()?;
    if let Some(suffix) = pat_parts.next()
        && !FORK_PRERELEASE_SUFFIXES.contains(&suffix)
    {
        return None;
    }
    Some((maj, min, pat))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn extracts_version_from_latest_tag() {
        assert_eq!(
            extract_version_from_latest_tag("rust-v1.5.0").expect("failed to parse version"),
            "1.5.0"
        );
    }

    #[test]
    fn latest_tag_without_prefix_is_invalid() {
        assert_eq!(
            extract_version_from_latest_tag("v1.5.0").expect("failed to parse version"),
            "1.5.0"
        );
        assert_eq!(
            extract_version_from_latest_tag("v1.5.0-termux").expect("failed to parse version"),
            "1.5.0"
        );
        assert!(extract_version_from_latest_tag("1.5.0").is_err());
    }

    #[test]
    fn prerelease_version_is_not_considered_newer() {
        assert_eq!(is_newer("0.11.0-beta.1", "0.11.0"), None);
        assert_eq!(is_newer("1.0.0-rc.1", "1.0.0"), None);
    }

    #[test]
    fn plain_semver_comparisons_work() {
        assert_eq!(is_newer("0.11.1", "0.11.0"), Some(true));
        assert_eq!(is_newer("0.11.0", "0.11.1"), Some(false));
        assert_eq!(is_newer("1.0.0", "0.9.9"), Some(true));
        assert_eq!(is_newer("0.9.9", "1.0.0"), Some(false));
    }

    #[test]
    fn source_build_version_is_not_checked() {
        assert!(is_source_build_version("0.0.0"));
        assert!(!is_source_build_version("0.1.0"));
    }

    #[test]
    fn whitespace_is_ignored() {
        assert_eq!(parse_version(" 1.2.3 \n"), Some((1, 2, 3)));
        assert_eq!(is_newer(" 1.2.3 ", "1.2.2"), Some(true));
    }

    #[test]
    fn termux_suffix_is_ignored() {
        assert_eq!(parse_version("1.2.3-termux"), Some((1, 2, 3)));
    }

    #[test]
    fn fork_prerelease_suffix_compares_as_its_patch_level() {
        assert_eq!(parse_version("0.153.3-agentcodi.1"), Some((0, 153, 3)));
        // The published patch level is not an update over the fork build of
        // that same patch level, but the next one is.
        assert_eq!(is_newer("0.153.3", "0.153.3-agentcodi.1"), Some(false));
        assert_eq!(is_newer("0.153.4", "0.153.3-agentcodi.1"), Some(true));
    }
}
