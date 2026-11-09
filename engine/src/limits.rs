pub const MAX_REDACT_STRING_CHARS: usize = 1_000_000;
pub const REDACTION_LIMIT_MARKER: &str = "[REDACTED: safe processing limit exceeded]";

pub fn fail_closed_for_oversize(input: &str) -> Option<String> {
    (input.chars().count() > MAX_REDACT_STRING_CHARS).then(|| REDACTION_LIMIT_MARKER.to_owned())
}
