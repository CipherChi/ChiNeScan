//! Bounded ZIP central-directory inspection. Member contents are never read or extracted.

const MAX_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 1_000;
const MAX_NAME_BYTES: usize = 4_096;
const MAX_RATIO: u64 = 1_000;
const EOCD_LEN: usize = 22;
const EOCD_SEARCH: usize = 65_535 + EOCD_LEN;

#[derive(Debug)]
pub struct Inspection {
    pub member_count: Option<usize>,
    pub names: Vec<String>,
    pub warnings: Vec<String>,
}

impl Inspection {
    pub fn failed(message: &str) -> Self {
        Self {
            member_count: None,
            names: Vec::new(),
            warnings: vec![message.to_owned()],
        }
    }
}

/// Inspect names and central-directory metadata only. No member data is decompressed.
pub fn inspect(data: &[u8]) -> Inspection {
    if data.len() > MAX_ARCHIVE_BYTES {
        return Inspection::failed("ZIP archive exceeds the 64 MiB metadata limit.");
    }
    let Some(eocd) = find_eocd(data) else {
        return Inspection::failed("ZIP end-of-central-directory record is missing or truncated.");
    };
    let disk = u16_at(data, eocd + 4).unwrap_or(u16::MAX);
    let directory_disk = u16_at(data, eocd + 6).unwrap_or(u16::MAX);
    let entries_on_disk = u16_at(data, eocd + 8).unwrap_or(u16::MAX) as usize;
    let entries = u16_at(data, eocd + 10).unwrap_or(u16::MAX) as usize;
    let directory_size = u32_at(data, eocd + 12).unwrap_or(u32::MAX) as usize;
    let directory_offset = u32_at(data, eocd + 16).unwrap_or(u32::MAX) as usize;
    if disk != 0 || directory_disk != 0 || entries != entries_on_disk {
        return Inspection::failed("Multi-disk ZIP archives are not supported.");
    }
    if entries == u16::MAX as usize
        || directory_size == u32::MAX as usize
        || directory_offset == u32::MAX as usize
    {
        return Inspection::failed("ZIP64 metadata is not supported by this bounded inspector.");
    }
    if entries > MAX_ENTRIES {
        return Inspection::failed("ZIP entry count exceeds the 1,000 entry limit.");
    }
    let Some(directory_end) = directory_offset.checked_add(directory_size) else {
        return Inspection::failed("ZIP central-directory bounds overflow.");
    };
    if directory_end > data.len() || directory_end > eocd {
        return Inspection::failed("ZIP central-directory bounds are invalid.");
    }

    let mut cursor = directory_offset;
    let mut names = Vec::with_capacity(entries);
    let mut warnings = Vec::new();
    let mut seen = std::collections::HashSet::with_capacity(entries);
    let mut declared_total = 0_u64;
    for _ in 0..entries {
        if u32_at(data, cursor) != Some(0x0201_4b50) {
            return Inspection::failed("ZIP central-directory entry is malformed or truncated.");
        }
        let Some(flags) = u16_at(data, cursor + 8) else {
            return Inspection::failed("ZIP central-directory entry is truncated.");
        };
        let Some(compressed) = u32_at(data, cursor + 20).map(u64::from) else {
            return Inspection::failed("ZIP central-directory entry is truncated.");
        };
        let Some(uncompressed) = u32_at(data, cursor + 24).map(u64::from) else {
            return Inspection::failed("ZIP central-directory entry is truncated.");
        };
        let name_len = u16_at(data, cursor + 28).unwrap_or(u16::MAX) as usize;
        let extra_len = u16_at(data, cursor + 30).unwrap_or(u16::MAX) as usize;
        let comment_len = u16_at(data, cursor + 32).unwrap_or(u16::MAX) as usize;
        let external_attributes = u32_at(data, cursor + 38).unwrap_or(0);
        let Some(name_start) = cursor.checked_add(46) else {
            return Inspection::failed("ZIP entry name bounds overflow.");
        };
        let Some(name_end) = name_start.checked_add(name_len) else {
            return Inspection::failed("ZIP entry name bounds overflow.");
        };
        let Some(entry_end) = name_end
            .checked_add(extra_len)
            .and_then(|value| value.checked_add(comment_len))
        else {
            return Inspection::failed("ZIP entry metadata bounds overflow.");
        };
        if name_len == 0 || name_len > MAX_NAME_BYTES || entry_end > directory_end {
            return Inspection::failed("ZIP entry has an invalid or oversized name/metadata.");
        }
        let name = String::from_utf8_lossy(&data[name_start..name_end]).into_owned();
        if unsafe_path(&name) {
            warnings.push("ZIP contains a path-traversal or absolute-path name.".to_owned());
        }
        if !seen.insert(name.clone()) {
            warnings.push("ZIP contains duplicate entry names.".to_owned());
        }
        if flags & 1 != 0 {
            warnings.push("ZIP contains an encrypted entry.".to_owned());
        }
        let unix_mode = (external_attributes >> 16) as u16;
        if unix_mode & 0o170000 == 0o120000 {
            warnings.push("ZIP contains a symbolic-link entry; target is not resolved.".to_owned());
        }
        if uncompressed > 0 {
            declared_total = declared_total.saturating_add(uncompressed);
            if compressed == 0 || uncompressed / compressed.max(1) > MAX_RATIO {
                warnings
                    .push("ZIP entry exceeds the 1,000:1 compression-ratio heuristic.".to_owned());
            }
        }
        if declared_total > MAX_ARCHIVE_BYTES as u64 {
            return Inspection::failed(
                "ZIP declared uncompressed size exceeds the 64 MiB metadata budget.",
            );
        }
        names.push(name);
        cursor = entry_end;
    }
    if cursor != directory_end {
        warnings.push("ZIP central-directory size does not match parsed entries.".to_owned());
    }
    Inspection {
        member_count: Some(entries),
        names,
        warnings,
    }
}

fn find_eocd(data: &[u8]) -> Option<usize> {
    let start = data.len().saturating_sub(EOCD_SEARCH);
    (start..=data.len().saturating_sub(EOCD_LEN))
        .rev()
        .find(|&offset| u32_at(data, offset) == Some(0x0605_4b50))
}

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn unsafe_path(name: &str) -> bool {
    let normalized = name.replace('\\', "/");
    normalized.starts_with('/')
        || normalized.starts_with("//")
        || normalized
            .split('/')
            .any(|part| part == ".." || part.contains(':'))
}

#[cfg(test)]
mod tests {
    use super::inspect;

    fn synthetic_zip(name: &[u8], flags: u16, compressed: u32, uncompressed: u32) -> Vec<u8> {
        let mut out = Vec::new();
        // Central-directory file header (the inspector intentionally does not inspect local data).
        out.extend_from_slice(&0x0201_4b50_u32.to_le_bytes());
        out.extend_from_slice(&0x0314_u16.to_le_bytes());
        out.extend_from_slice(&20_u16.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&0_u32.to_le_bytes());
        out.extend_from_slice(&compressed.to_le_bytes());
        out.extend_from_slice(&uncompressed.to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&0_u32.to_le_bytes());
        out.extend_from_slice(&0_u32.to_le_bytes());
        out.extend_from_slice(name);
        let directory_size = out.len() as u32;
        out.extend_from_slice(&0x0605_4b50_u32.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&1_u16.to_le_bytes());
        out.extend_from_slice(&1_u16.to_le_bytes());
        out.extend_from_slice(&directory_size.to_le_bytes());
        out.extend_from_slice(&0_u32.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out
    }

    #[test]
    fn lists_names_without_reading_member_contents() {
        let archive = synthetic_zip(b"docs/readme.txt", 0, 5, 5);
        let result = inspect(&archive);
        assert_eq!(result.member_count, Some(1));
        assert_eq!(result.names, ["docs/readme.txt"]);
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn detects_traversal_backslash_absolute_and_encryption() {
        for name in [
            b"../escape".as_slice(),
            b"..\\escape",
            b"C:\\temp\\x",
            b"/root",
        ] {
            let result = inspect(&synthetic_zip(name, 1, 1, 10));
            assert!(result
                .warnings
                .iter()
                .any(|warning| warning.contains("path-traversal")));
            assert!(result
                .warnings
                .iter()
                .any(|warning| warning.contains("encrypted")));
        }
    }

    #[test]
    fn rejects_truncated_and_oversized_inputs_cleanly() {
        assert_eq!(inspect(b"PK\x05\x06").member_count, None);
        let too_large = vec![0; 64 * 1024 * 1024 + 1];
        assert!(inspect(&too_large).warnings[0].contains("64 MiB"));
        let declared_bomb = synthetic_zip(b"large.bin", 0, 1, 64 * 1024 * 1024 + 1);
        assert!(inspect(&declared_bomb).warnings[0].contains("declared uncompressed size"));
    }
}
