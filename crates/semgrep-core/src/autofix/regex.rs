//! Regex-based fix template: `rule.fix_regex { regex, replacement, count? }`.

use crate::FixRegex;

/// Apply a [`FixRegex`] to `text`. If `count` is `Some(n)`, perform up to `n`
/// substitutions (a la `Regex::replacen`); otherwise replace every occurrence.
pub fn apply_fix_regex(text: &str, fix: &FixRegex) -> Result<String, crate::SemgrepError> {
    let re = regex::Regex::new(&fix.regex)?;
    if let Some(n) = fix.count {
        // `replacen` takes a count; 0 means unlimited per `regex` docs.
        Ok(re.replacen(text, n, fix.replacement.as_str()).into_owned())
    } else {
        Ok(re.replace_all(text, fix.replacement.as_str()).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_all_by_default() {
        let fr = FixRegex {
            regex: "foo".into(),
            replacement: "bar".into(),
            count: None,
        };
        assert_eq!(apply_fix_regex("foo foo", &fr).unwrap(), "bar bar");
    }

    #[test]
    fn replacen_honoured() {
        let fr = FixRegex {
            regex: "foo".into(),
            replacement: "bar".into(),
            count: Some(1),
        };
        assert_eq!(apply_fix_regex("foo foo", &fr).unwrap(), "bar foo");
    }

    #[test]
    fn capture_group_replacement() {
        let fr = FixRegex {
            regex: r"(\w+)\.loads".into(),
            replacement: "json.loads".into(),
            count: None,
        };
        assert_eq!(
            apply_fix_regex("pickle.loads(data)", &fr).unwrap(),
            "json.loads(data)"
        );
    }
}
