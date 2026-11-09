use regex::{Regex, RegexBuilder};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use crate::limits::fail_closed_for_oversize;

pub const REDACTED: &str = "[REDACTED]";
const MAX_SENSITIVE_KEY_CHARS: usize = 256;

static ARGON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\$argon2(?:id|i|d)\$[^\s\x{1c}-\x{1f}"';}]+"#).expect("constant Argon regex")
});
static TOKEN_RUN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9_-]{32,}").expect("constant token regex"));
static PYTHON_ALPHA: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\p{L}").expect("constant Unicode letter regex"));
static PYTHON_ALNUM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[\p{L}\p{N}]").expect("constant Unicode alphanumeric regex"));
static ENV_PATTERNS: LazyLock<Mutex<HashMap<String, Regex>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn is_sensitive_key(key: &str) -> bool {
    let lowered: String = key
        .chars()
        .map(|ch| match ch {
            '\u{0130}' | '\u{0131}' => 'i',
            '\u{017f}' => 's',
            '\u{212a}' => 'k',
            other => other,
        })
        .flat_map(char::to_lowercase)
        .collect();
    [
        "password",
        "passwd",
        "pwd",
        "hash",
        "token",
        "secret",
        "api_key",
        "api-key",
        "apikey",
        "authorization",
        "cookie",
        "session",
        "csrf",
        "credential",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

fn is_sensitive_key_bounded(key: &str) -> bool {
    if key.eq_ignore_ascii_case("tokenResponse") {
        return false;
    }
    let start = key
        .char_indices()
        .rev()
        .nth(MAX_SENSITIVE_KEY_CHARS - 1)
        .map_or(0, |(byte_index, _)| byte_index);
    is_sensitive_key(&key[start..])
}

fn previous_char_start(value: &str, index: usize) -> usize {
    if index == 0 {
        return 0;
    }
    let mut start = index - 1;
    while !value.is_char_boundary(start) {
        start -= 1;
    }
    start
}

fn character_matches(pattern: &Regex, ch: char) -> bool {
    let mut encoded = [0_u8; 4];
    pattern.is_match(ch.encode_utf8(&mut encoded))
}

fn key_char(ch: char) -> bool {
    if ch.is_ascii() {
        ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-')
    } else {
        character_matches(&PYTHON_ALNUM, ch)
    }
}

fn valid_key_start(ch: char) -> bool {
    if ch.is_ascii() {
        ch.is_ascii_alphabetic() || ch == '_'
    } else {
        character_matches(&PYTHON_ALPHA, ch)
    }
}

fn is_python_space(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '\u{001c}'..='\u{001f}')
}

fn assignment_value_end(value: &str, start: usize) -> Option<(usize, char)> {
    let first = value.get(start..)?.chars().next()?;
    if matches!(first, '\'' | '"') {
        let mut cursor = start + first.len_utf8();
        let mut escaped = false;
        while cursor < value.len() {
            let ch = value[cursor..].chars().next()?;
            if !escaped && ch == first {
                let end = cursor + ch.len_utf8();
                return Some((end, first));
            }
            if ch == '\n' || (!escaped && ch == '\r') {
                break;
            }
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            }
            cursor += ch.len_utf8();
        }
    } else if first == '<' {
        if let Some(offset) = value[start + 1..].find('>') {
            return Some((start + 1 + offset + 1, '<'));
        }
    }

    let mut cursor = start;
    for (offset, ch) in value[start..].char_indices() {
        if ch.is_whitespace() || matches!(ch, ',' | ';' | '}' | ']') {
            if offset == 0 {
                return None;
            }
            cursor = start + offset;
            break;
        }
        cursor = start + offset + ch.len_utf8();
    }
    (cursor > start).then_some((cursor, '\0'))
}

fn redact_assignments(value: &str) -> String {
    let mut output = String::new();
    let mut cursor = 0;
    let mut search_from = 0;

    while search_from < value.len() {
        let Some(relative_delimiter) = value[search_from..].find([':', '=']) else {
            break;
        };
        let delimiter = search_from + relative_delimiter;

        let mut key_end = delimiter;
        while key_end > search_from {
            let start = previous_char_start(value, key_end);
            if value[start..key_end]
                .chars()
                .next()
                .is_some_and(is_python_space)
            {
                key_end = start;
            } else {
                break;
            }
        }
        if key_end > search_from {
            let before_quote = previous_char_start(value, key_end);
            if matches!(
                value[before_quote..key_end].chars().next(),
                Some('\'' | '"')
            ) {
                key_end = before_quote;
            }
        }

        let mut key_start = key_end;
        while key_start > search_from {
            let start = previous_char_start(value, key_start);
            if value[start..key_start].chars().next().is_some_and(key_char) {
                key_start = start;
            } else {
                break;
            }
        }
        let key = &value[key_start..key_end];
        let valid = key.chars().next().is_some_and(valid_key_start);
        if value.as_bytes()[delimiter] == b':' {
            let mut path_value_start = delimiter + 1;
            while path_value_start < value.len() {
                let ch = value[path_value_start..]
                    .chars()
                    .next()
                    .expect("valid UTF-8 boundary");
                if is_python_space(ch) {
                    path_value_start += ch.len_utf8();
                } else {
                    break;
                }
            }
            let could_be_digit_value = value[path_value_start..]
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_digit() || matches!(ch, '\'' | '"'));
            if could_be_digit_value {
                if let Some((end, _)) = assignment_value_end(value, path_value_start) {
                    if value[path_value_start..end]
                        .chars()
                        .all(|ch| ch.is_ascii_digit())
                    {
                        let preceding = value[..delimiter]
                            .split(|ch: char| {
                                ch.is_whitespace() || matches!(ch, '\u{001c}'..='\u{001f}')
                            })
                            .next_back()
                            .unwrap_or("");
                        let lowered = preceding.to_ascii_lowercase();
                        let path_like = preceding.contains('/')
                            || preceding.contains('\\')
                            || [
                                ".py", ".js", ".ts", ".tsx", ".jsx", ".rs", ".go", ".java", ".cs",
                                ".rb", ".php", ".sh", ".ps1",
                            ]
                            .iter()
                            .any(|extension| lowered.ends_with(extension));
                        if path_like {
                            search_from = delimiter + 1;
                            continue;
                        }
                    }
                }
            }
        }

        if valid && is_sensitive_key_bounded(key) {
            let mut value_start = delimiter + 1;
            while value_start < value.len() {
                let ch = value[value_start..]
                    .chars()
                    .next()
                    .expect("valid UTF-8 boundary");
                if is_python_space(ch) {
                    value_start += ch.len_utf8();
                } else {
                    break;
                }
            }
            if let Some((end, quote)) = assignment_value_end(value, value_start) {
                output.push_str(&value[cursor..value_start]);
                match quote {
                    '\'' => output.push_str("'[REDACTED]'"),
                    '"' => output.push_str("\"[REDACTED]\""),
                    '<' => output.push_str("<[REDACTED]>"),
                    _ => output.push_str(REDACTED),
                }
                cursor = end;
                search_from = end;
                continue;
            }
        }
        search_from = delimiter + 1;
    }

    if output.is_empty() {
        value.to_owned()
    } else {
        output.push_str(&value[cursor..]);
        output
    }
}

fn is_windows_prefix(value: &str, at: usize) -> Option<usize> {
    let bytes = value.as_bytes();
    let drive = value.get(at..)?.chars().next()?;
    let drive_end = at + drive.len_utf8();
    let is_python_case_insensitive_ascii = drive.is_ascii_alphabetic()
        || matches!(drive, '\u{0130}' | '\u{0131}' | '\u{017f}' | '\u{212a}');
    if is_python_case_insensitive_ascii
        && bytes
            .get(drive_end..drive_end + 2)
            .is_some_and(|pair| pair == &b":\\"[..])
    {
        Some(drive_end + 2)
    } else if at + 2 <= bytes.len() && bytes[at] == b'\\' && bytes[at + 1] == b'\\' {
        Some(at + 2)
    } else {
        None
    }
}

fn is_path_stop(ch: char) -> bool {
    is_python_space(ch)
        || matches!(
            ch,
            '"' | '\'' | '<' | '>' | '`' | ',' | ';' | ')' | '}' | ']'
        )
}

fn replace_quoted_windows_paths(value: &str) -> String {
    let mut output = String::new();
    let mut cursor = 0;
    let mut scan = 0;
    while scan < value.len() {
        let quote = value[scan..].chars().next().expect("valid UTF-8 boundary");
        if !matches!(quote, '\'' | '"') {
            scan += quote.len_utf8();
            continue;
        }
        let path_start = scan + quote.len_utf8();
        if let Some(path_end) = is_windows_prefix(value, path_start) {
            let close = value[path_end..].find(['\'', '"']).map(|at| path_end + at);
            if let Some(close) = close {
                if value[close..].starts_with(quote) && close > path_end {
                    output.push_str(&value[cursor..scan]);
                    output.push(quote);
                    output.push_str("[PATH]");
                    output.push(quote);
                    cursor = close + quote.len_utf8();
                    scan = cursor;
                    continue;
                }
            }
        }
        scan += quote.len_utf8();
    }
    output.push_str(&value[cursor..]);
    output
}

fn is_python_word(ch: char) -> bool {
    character_matches(&PYTHON_ALNUM, ch) || ch == '_'
}

fn replace_windows_paths(value: &str) -> String {
    let mut output = String::new();
    let mut cursor = 0;
    let mut scan = 0;
    while scan < value.len() {
        if let Some(path_start) = is_windows_prefix(value, scan) {
            let boundary_ok = scan == 0
                || !value[..scan]
                    .chars()
                    .next_back()
                    .is_some_and(is_python_word);
            if boundary_ok {
                let mut end = path_start;
                for (offset, ch) in value[path_start..].char_indices() {
                    if is_path_stop(ch) {
                        end = path_start + offset;
                        break;
                    }
                    end = path_start + offset + ch.len_utf8();
                }
                if end > path_start {
                    output.push_str(&value[cursor..scan]);
                    output.push_str("[PATH]");
                    cursor = end;
                    scan = end;
                    continue;
                }
            }
        }
        let ch = value[scan..].chars().next().expect("valid UTF-8 boundary");
        scan += ch.len_utf8();
    }
    output.push_str(&value[cursor..]);
    output
}

fn posix_root_end(value: &str, at: usize) -> Option<usize> {
    [
        "/Users/",
        "/home/",
        "/root/",
        "/tmp/",
        "/var/tmp/",
        "/private/tmp/",
        "/var/folders/",
        "/etc/",
        "/opt/",
        "/mnt/",
    ]
    .iter()
    .find_map(|root| value[at..].starts_with(root).then_some(at + root.len()))
}

fn replace_posix_paths(value: &str) -> String {
    let mut output = String::new();
    let mut cursor = 0;
    let mut scan = 0;
    while scan < value.len() {
        let boundary_ok = scan == 0
            || !value[..scan]
                .chars()
                .next_back()
                .is_some_and(|ch| is_python_word(ch) || matches!(ch, ':' | '/'));
        if value.as_bytes()[scan] == b'/' && boundary_ok {
            if let Some(path_start) = posix_root_end(value, scan) {
                let mut end = path_start;
                for (offset, ch) in value[path_start..].char_indices() {
                    if is_path_stop(ch) {
                        end = path_start + offset;
                        break;
                    }
                    end = path_start + offset + ch.len_utf8();
                }
                if end > path_start {
                    output.push_str(&value[cursor..scan]);
                    output.push_str("[PATH]");
                    cursor = end;
                    scan = end;
                    continue;
                }
            }
        }
        let ch = value[scan..].chars().next().expect("valid UTF-8 boundary");
        scan += ch.len_utf8();
    }
    output.push_str(&value[cursor..]);
    output
}

fn env_pattern(root: &str) -> Option<Regex> {
    let mut cache = ENV_PATTERNS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(pattern) = cache.get(root) {
        return Some(pattern.clone());
    }
    let pattern = RegexBuilder::new(&regex::escape(root))
        .case_insensitive(true)
        .build()
        .ok()?;
    cache.insert(root.to_owned(), pattern.clone());
    Some(pattern)
}

fn replace_env_paths(value: &str) -> String {
    let mut output = value.to_owned();
    for name in [
        "USERPROFILE",
        "HOME",
        "TEMP",
        "TMP",
        "APPDATA",
        "LOCALAPPDATA",
        "CHINESCAN_CONFIG_PATH",
        "CHINESCAN_DATABASE_PATH",
        "CHINESCAN_REPORTS_DIR",
    ] {
        if let Some(root) = std::env::var_os(name).and_then(|entry| entry.into_string().ok()) {
            if !root.is_empty() {
                if let Some(pattern) = env_pattern(&root) {
                    output = pattern.replace_all(&output, "[PATH]").into_owned();
                }
            }
        }
    }
    output
}

fn replace_bearer_values(value: &str) -> String {
    let mut output = String::new();
    let mut cursor = 0;
    let mut scan = 0;
    let bytes = value.as_bytes();
    while scan + 6 <= bytes.len() {
        let bearer_prefix = bytes[scan..scan + 6].eq_ignore_ascii_case(b"Bearer");
        let boundary_ok = scan == 0
            || !value[..scan]
                .chars()
                .next_back()
                .is_some_and(is_python_word);
        if !bearer_prefix || !boundary_ok {
            let ch = value[scan..].chars().next().expect("valid UTF-8 boundary");
            scan += ch.len_utf8();
            continue;
        }

        let mut end = scan + 6;
        let whitespace_start = end;
        while end < value.len() {
            let ch = value[end..].chars().next().expect("valid UTF-8 boundary");
            if is_python_space(ch) {
                end += ch.len_utf8();
            } else {
                break;
            }
        }
        if end == whitespace_start {
            let ch = value[scan..].chars().next().expect("valid UTF-8 boundary");
            scan += ch.len_utf8();
            continue;
        }

        let token_start = end;
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric()
                || matches!(bytes[end], b'.' | b'_' | b'~' | b'+' | b'/' | b'-'))
        {
            end += 1;
        }
        if end == token_start {
            let ch = value[scan..].chars().next().expect("valid UTF-8 boundary");
            scan += ch.len_utf8();
            continue;
        }
        while end < bytes.len() && bytes[end] == b'=' {
            end += 1;
        }
        output.push_str(&value[cursor..scan]);
        output.push_str("Bearer [REDACTED]");
        cursor = end;
        scan = end;
    }
    if cursor == 0 {
        value.to_owned()
    } else {
        output.push_str(&value[cursor..]);
        output
    }
}

fn is_uuid(candidate: &str) -> bool {
    let bytes = candidate.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23].iter().all(|index| bytes[*index] == b'-')
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 8 | 13 | 18 | 23) || byte.is_ascii_hexdigit())
        && matches!(bytes[14].to_ascii_lowercase(), b'1'..=b'8')
        && matches!(bytes[19].to_ascii_lowercase(), b'8'..=b'b')
}

fn is_hex(candidate: &str) -> bool {
    candidate.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn redact_token_runs(value: &str) -> String {
    let mut output = String::new();
    let mut cursor = 0;
    for found in TOKEN_RUN.find_iter(value) {
        let start = found.start();
        let end = found.end();
        let candidate = found.as_str();
        let left_boundary = start == 0
            || !value[..start]
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'));
        let right_boundary = end == value.len()
            || !value[end..]
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'));
        if !left_boundary || !right_boundary {
            continue;
        }
        let has_letters = candidate.chars().any(|ch| ch.is_ascii_alphabetic());
        let high_entropy_shape = has_letters
            && (candidate.chars().any(|ch| ch.is_ascii_digit())
                || (candidate.chars().any(|ch| ch.is_ascii_lowercase())
                    && candidate.chars().any(|ch| ch.is_ascii_uppercase())));
        if is_uuid(candidate) || is_hex(candidate) || !high_entropy_shape {
            continue;
        }
        output.push_str(&value[cursor..start]);
        output.push_str(REDACTED);
        cursor = end;
    }
    if cursor == 0 {
        value.to_owned()
    } else {
        output.push_str(&value[cursor..]);
        output
    }
}

pub fn redact_text(input: &str) -> String {
    if let Some(marker) = fail_closed_for_oversize(input) {
        return marker;
    }
    let mut value = redact_assignments(input);
    value = ARGON.replace_all(&value, REDACTED).into_owned();
    value = replace_bearer_values(&value);
    value = replace_env_paths(&value);
    value = replace_quoted_windows_paths(&value);
    value = replace_windows_paths(&value);
    value = replace_posix_paths(&value);
    redact_token_runs(&value)
}

#[cfg(test)]
mod tests {
    use super::redact_text;
    use crate::limits::REDACTION_LIMIT_MARKER;

    #[test]
    fn token_url_safe_mixed_classes_redacted() {
        assert_eq!(
            redact_text("CanaryToken1234567890abcdefghijklmnopqrstuv"),
            "[REDACTED]"
        );
    }

    #[test]
    fn token_alphanumeric_lowercase_preserved() {
        assert_eq!(redact_text(&"a".repeat(32)), "a".repeat(32));
    }

    #[test]
    fn token_alphanumeric_uppercase_preserved() {
        assert_eq!(redact_text(&"A".repeat(32)), "A".repeat(32));
    }

    #[test]
    fn token_numeric_only_preserved() {
        assert_eq!(redact_text(&"7".repeat(32)), "7".repeat(32));
    }

    #[test]
    fn lowercase_identifier_with_underscore_is_preserved() {
        assert_eq!(
            redact_text(&format!("{}{}", "a".repeat(31), "_")),
            format!("{}{}", "a".repeat(31), "_")
        );
    }

    #[test]
    fn code_symbol_and_project_location_are_preserved() {
        assert_eq!(
            redact_text("def get_api_key_status(self): scripts/secret_rotation_audit.py:101"),
            "def get_api_key_status(self): scripts/secret_rotation_audit.py:101"
        );
    }

    #[test]
    fn source_path_and_line_number_are_preserved() {
        let input = "scripts/secret_rotation_audit.py:101";
        assert_eq!(redact_text(input), input);
    }

    #[test]
    fn token_embedded_in_ascii_word_preserved() {
        let value = format!("x{}", "a".repeat(32));
        assert_eq!(redact_text(&value), value);
    }

    #[test]
    fn token_followed_by_ascii_word_preserved() {
        let value = format!("{}x", "a".repeat(32));
        assert_eq!(redact_text(&value), value);
    }

    #[test]
    fn token_after_punctuation_redacted() {
        assert_eq!(
            redact_text(&format!("!{}", "Ab9_".repeat(8))),
            "![REDACTED]"
        );
    }

    #[test]
    fn api_key_assignment_redacted() {
        assert_eq!(redact_text("apiKey=synthetic-canary"), "apiKey=[REDACTED]");
    }

    #[test]
    fn api_key_underscore_assignment_redacted() {
        assert_eq!(
            redact_text("api_key=synthetic-canary"),
            "api_key=[REDACTED]"
        );
    }

    #[test]
    fn sensitive_password_key_redacted() {
        assert_eq!(redact_text("password=value"), "password=[REDACTED]");
    }

    #[test]
    fn sensitive_cookie_key_redacted_case_insensitively() {
        assert_eq!(redact_text("Cookie: value"), "Cookie: [REDACTED]");
    }

    #[test]
    fn python_unicode_casefold_specials_match_sensitive_literals() {
        assert_eq!(redact_text("paſsword=value"), "paſsword=[REDACTED]");
        assert_eq!(redact_text("apiKey=value"), "apiKey=[REDACTED]");
        assert_eq!(redact_text("apıkey=value"), "apıkey=[REDACTED]");
    }

    #[test]
    fn quoted_double_assignment_keeps_quotes() {
        assert_eq!(
            redact_text("password=\"secret\""),
            "password=\"[REDACTED]\""
        );
    }

    #[test]
    fn quoted_single_assignment_keeps_quotes() {
        assert_eq!(redact_text("pwd='secret'"), "pwd='[REDACTED]'");
    }

    #[test]
    fn angle_assignment_keeps_brackets() {
        assert_eq!(redact_text("token=<secret>"), "token=<[REDACTED]>");
    }

    #[test]
    fn unquoted_assignment_uses_plain_marker() {
        assert_eq!(
            redact_text("password=secret; safe=1"),
            "password=[REDACTED]; safe=1"
        );
    }

    #[test]
    fn quoted_key_assignment_redacted() {
        assert_eq!(
            redact_text("\"password_hash\": \"hash\""),
            "\"password_hash\": \"[REDACTED]\""
        );
    }

    #[test]
    fn long_sensitive_key_assignment_redacted() {
        let key = format!("{}_secret=synthetic-canary", "x".repeat(1_000));
        assert!(redact_text(&key).ends_with("[REDACTED]"));
    }

    #[test]
    fn long_key_preserves_key_and_redacts_only_value() {
        let input = format!("{}_secret=abc", "x".repeat(300));
        let expected = format!("{}_secret=[REDACTED]", "x".repeat(300));
        assert_eq!(redact_text(&input), expected);
    }

    #[test]
    fn plain_hex_digest_is_preserved() {
        assert_eq!(redact_text(&"c".repeat(64)), "c".repeat(64));
    }

    #[test]
    fn valid_uuid_is_preserved() {
        let uuid = "123e4567-e89b-12d3-a456-426614174000";
        assert_eq!(redact_text(uuid), uuid);
    }

    #[test]
    fn invalid_uuid_shape_is_redacted() {
        let uuid = "123e4567-e89b-02d3-a456-426614174000";
        assert_eq!(redact_text(uuid), "[REDACTED]");
    }

    #[test]
    fn argon2id_hash_redacted() {
        assert_eq!(
            redact_text("$argon2id$v=19$m=65536,t=3,p=4$salt$hash"),
            "[REDACTED]"
        );
    }

    #[test]
    fn argon2i_hash_redacted() {
        assert_eq!(
            redact_text("$argon2i$v=19$m=65536,t=3,p=4$salt$hash"),
            "[REDACTED]"
        );
    }

    #[test]
    fn argon2d_hash_redacted() {
        assert_eq!(
            redact_text("$argon2d$v=19$m=65536,t=3,p=4$salt$hash"),
            "[REDACTED]"
        );
    }

    #[test]
    fn bearer_token_redacted() {
        assert_eq!(redact_text("Bearer abc.def-123"), "Bearer [REDACTED]");
    }

    #[test]
    fn jwt_bearer_shape_redacted() {
        assert_eq!(
            redact_text("Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJjYW5hcnkifQ.signature"),
            "Bearer [REDACTED]"
        );
    }

    #[test]
    fn windows_path_redacted() {
        assert_eq!(redact_text("at C:\\Users\\Cipher\\secret.txt"), "at [PATH]");
    }

    #[test]
    fn quoted_windows_path_retains_quotes() {
        assert_eq!(
            redact_text("at \"C:\\Users\\Cipher\\secret.txt\""),
            "at \"[PATH]\""
        );
    }

    #[test]
    fn unc_path_redacted() {
        assert_eq!(redact_text(r"at \\server\share\private.txt"), "at [PATH]");
    }

    #[test]
    fn posix_home_path_redacted() {
        assert_eq!(redact_text("at /home/operator/secret.txt"), "at [PATH]");
    }

    #[test]
    fn posix_root_path_redacted() {
        assert_eq!(redact_text("at /opt/chinescan/private"), "at [PATH]");
    }

    #[test]
    fn posix_etc_path_redacted() {
        assert_eq!(redact_text("at /etc/chinescan/config"), "at [PATH]");
    }

    #[test]
    fn location_suffix_marker_is_not_redacted() {
        let input = "location: [REDACTED]";
        assert_eq!(redact_text(input), input);
    }

    #[test]
    fn mismatched_redaction_brackets_are_not_created() {
        let input = "[REDACTED]]] [REDACTED]]";
        assert_eq!(redact_text(input), input);
    }

    #[test]
    fn empty_string_is_preserved() {
        assert_eq!(redact_text(""), "");
    }

    #[test]
    fn non_ascii_plain_text_is_preserved() {
        let input = "安全日志 café 東京";
        assert_eq!(redact_text(input), input);
    }

    #[test]
    fn unicode_sensitive_key_is_supported() {
        assert_eq!(redact_text("密码=value"), "密码=value");
    }

    #[test]
    fn adversarial_long_benign_text_is_preserved() {
        let input = "x".repeat(100_000);
        assert_eq!(redact_text(&input), input);
    }

    #[test]
    fn adversarial_repeated_delimiters_remain_linear_and_safe() {
        let started = std::time::Instant::now();
        let input = format!("{}{}", "x:".repeat(50_000), "password=secret");
        assert!(redact_text(&input).ends_with("password=[REDACTED]"));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn adversarial_long_near_key_is_safe() {
        let input = format!("{}x=harmless", "x".repeat(50_000));
        assert_eq!(redact_text(&input), input);
    }

    #[test]
    fn exactly_at_size_limit_is_processed() {
        let input = "x".repeat(1_000_000);
        assert_eq!(redact_text(&input), input);
    }

    #[test]
    fn oversize_input_fails_closed_with_python_marker() {
        let input = "x".repeat(1_000_001);
        assert_eq!(redact_text(&input), REDACTION_LIMIT_MARKER);
    }
}
