//! Redaction: replace secret substrings with stable placeholders before a capture is committed or
//! snapshotted. One routine, shared by error-excerpt tests now and the support-bundle test later.

/// A single literal replacement. Matching is plain substring (no regex), applied in order.
#[derive(Debug, Clone)]
pub struct RedactRule {
    pub needle: String,
    pub placeholder: String,
}

impl RedactRule {
    /// Replace every occurrence of `needle` with `placeholder`.
    pub fn new(needle: impl Into<String>, placeholder: impl Into<String>) -> Self {
        Self {
            needle: needle.into(),
            placeholder: placeholder.into(),
        }
    }
}

/// Apply every rule in order, returning the redacted text. Rules with an empty needle are skipped
/// so a blank secret can't blow up into a placeholder between every char.
#[must_use]
pub fn redact(input: &str, rules: &[RedactRule]) -> String {
    let mut out = input.to_owned();
    for rule in rules {
        if rule.needle.is_empty() {
            continue;
        }
        out = out.replace(&rule.needle, &rule.placeholder);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_every_occurrence() {
        let rules = [RedactRule::new("hunter2", "<password>")];
        assert_eq!(
            redact("user=me pw=hunter2 retry=hunter2", &rules),
            "user=me pw=<password> retry=<password>",
        );
    }

    #[test]
    fn rules_apply_in_order() {
        let rules = [
            RedactRule::new("sid=abc123", "sid=<session>"),
            RedactRule::new("abc123", "<leftover>"),
        ];
        assert_eq!(
            redact("sid=abc123 x=abc123", &rules),
            "sid=<session> x=<leftover>"
        );
    }

    #[test]
    fn empty_needle_is_a_no_op() {
        let rules = [RedactRule::new("", "<nope>")];
        assert_eq!(redact("unchanged", &rules), "unchanged");
    }
}
