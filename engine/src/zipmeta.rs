//! Bounded ZIP central-directory inspection. Member contents are never read or extracted.

use std::io::{Cursor, Read};

use flate2::read::GzDecoder;

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
    pub findings: Vec<ArchiveFinding>,
}

#[derive(Debug, Clone)]
pub struct ArchiveFinding {
    pub id: String,
    pub rule_id: &'static str,
    pub severity: &'static str,
    pub confidence: f32,
    pub entry_path: String,
    pub explanation: &'static str,
}

impl Inspection {
    pub fn failed(message: &str) -> Self {
        Self {
            member_count: None,
            names: Vec::new(),
            warnings: vec![message.to_owned()],
            findings: Vec::new(),
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
    let mut findings = Vec::new();
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
        let dos_time = u16_at(data, cursor + 12).unwrap_or(0);
        let dos_date = u16_at(data, cursor + 14).unwrap_or(0);
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
            warnings.push("ZIP contains a path traversal or absolute-path entry name.".to_owned());
            findings.push(finding(
                "archive.path_traversal",
                "high",
                0.99,
                &name,
                "Entry path is absolute, contains a drive prefix, or escapes its archive root.",
            ));
        }
        let normalized_name = name.replace('\\', "/");
        if !seen.insert(normalized_name) {
            warnings.push("ZIP contains duplicate entry names.".to_owned());
            findings.push(finding(
                "archive.duplicate_entry",
                "medium",
                0.99,
                &name,
                "Archive contains the same normalized entry name more than once.",
            ));
        }
        if flags & 1 != 0 {
            warnings.push("ZIP contains an encrypted entry.".to_owned());
            findings.push(finding(
                "archive.encrypted_entry",
                "medium",
                0.98,
                &name,
                "Entry is encrypted; its content was not inspected.",
            ));
        }
        let unix_mode = (external_attributes >> 16) as u16;
        if unix_mode & 0o170000 == 0o120000 {
            warnings.push("ZIP contains a symbolic-link entry; target is not resolved.".to_owned());
            findings.push(finding(
                "archive.symlink_entry",
                "high",
                0.95,
                &name,
                "Archive contains a symbolic link; its target was not read or resolved.",
            ));
        }
        if uncompressed > 0 {
            declared_total = declared_total.saturating_add(uncompressed);
            if compressed == 0 || uncompressed / compressed.max(1) > MAX_RATIO {
                warnings
                    .push("ZIP entry exceeds the 1,000:1 compression-ratio heuristic.".to_owned());
                findings.push(finding(
                    "archive.compression_ratio",
                    "high",
                    0.90,
                    &name,
                    "Declared entry compression ratio exceeds the 1,000:1 triage threshold.",
                ));
            }
        }
        if nested_archive_name(&name) {
            findings.push(finding(
                "archive.nested_archive",
                "low",
                0.90,
                &name,
                "Entry name indicates a nested archive; nested contents are not opened.",
            ));
        }
        if double_extension(&name) {
            findings.push(finding("archive.double_extension", "medium", 0.82, &name, "Entry has a document or image extension followed by an executable or script extension."));
        }
        let _metadata = (compressed, uncompressed, dos_time, dos_date, unix_mode);
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
        findings,
    }
}

/// List TAR or TAR.GZ headers in memory. Gzip output is capped before TAR parsing.
pub fn inspect_tar(data: &[u8], compressed: bool) -> Inspection {
    if data.len() > MAX_ARCHIVE_BYTES {
        return Inspection::failed("TAR input exceeds the 64 MiB input limit.");
    }
    let mut tar_bytes = Vec::new();
    if compressed {
        let decoder = GzDecoder::new(data);
        if decoder
            .take((MAX_ARCHIVE_BYTES + 1) as u64)
            .read_to_end(&mut tar_bytes)
            .is_err()
            || tar_bytes.len() > MAX_ARCHIVE_BYTES
        {
            return Inspection::failed(
                "TAR.GZ expansion exceeds the 64 MiB in-memory limit or is malformed.",
            );
        }
    } else {
        tar_bytes.extend_from_slice(data);
    }
    let expanded_len = tar_bytes.len();
    let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
    let entries = match archive.entries() {
        Ok(entries) => entries,
        Err(_) => return Inspection::failed("TAR header stream is malformed."),
    };
    let mut names = Vec::new();
    let mut warnings = Vec::new();
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut declared_total = 0_u64;
    for (index, entry_result) in entries.enumerate() {
        if index >= MAX_ENTRIES {
            return Inspection::failed("TAR entry count exceeds the 1,000 entry limit.");
        }
        let Ok(entry) = entry_result else {
            warnings.push("TAR contains a malformed or truncated entry.".to_owned());
            break;
        };
        let name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        let size = entry.size();
        declared_total = declared_total.saturating_add(size);
        if declared_total > MAX_ARCHIVE_BYTES as u64 {
            return Inspection::failed(
                "TAR declared expanded size exceeds the 64 MiB metadata budget.",
            );
        }
        if unsafe_path(&name) {
            findings.push(finding(
                "archive.path_traversal",
                "high",
                0.99,
                &name,
                "Entry path is absolute, contains a drive prefix, or escapes its archive root.",
            ));
        }
        let normalized_name = name.replace('\\', "/");
        if !seen.insert(normalized_name) {
            findings.push(finding(
                "archive.duplicate_entry",
                "medium",
                0.99,
                &name,
                "Archive contains the same normalized entry name more than once.",
            ));
        }
        if entry.header().entry_type().is_symlink() || entry.header().entry_type().is_hard_link() {
            findings.push(finding(
                "archive.link_entry",
                "high",
                0.95,
                &name,
                "Archive contains a link entry; its target is not resolved.",
            ));
            if let Some(target) = entry.link_name_bytes() {
                let target = String::from_utf8_lossy(&target).into_owned();
                if unsafe_path(&target) {
                    findings.push(finding(
                        "archive.link_escape",
                        "high",
                        0.97,
                        &name,
                        "Link target appears to escape the archive root.",
                    ));
                }
            }
        }
        if nested_archive_name(&name) {
            findings.push(finding(
                "archive.nested_archive",
                "low",
                0.90,
                &name,
                "Entry name indicates a nested archive; nested contents are not opened.",
            ));
        }
        if double_extension(&name) {
            findings.push(finding("archive.double_extension", "medium", 0.82, &name, "Entry has a document or image extension followed by an executable or script extension."));
        }
        names.push(name);
    }
    if compressed && !data.is_empty() && expanded_len as u64 / data.len() as u64 > MAX_RATIO {
        findings.push(finding(
            "archive.compression_ratio",
            "high",
            0.90,
            "",
            "TAR.GZ expanded size exceeds the 1,000:1 archive compression-ratio heuristic.",
        ));
    }
    Inspection {
        member_count: Some(names.len()),
        names,
        warnings,
        findings,
    }
}

fn finding(
    rule_id: &'static str,
    severity: &'static str,
    confidence: f32,
    path: &str,
    explanation: &'static str,
) -> ArchiveFinding {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in rule_id.bytes().chain([0]).chain(path.bytes()) {
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
    }
    ArchiveFinding {
        id: format!("archive-{hash:016x}"),
        rule_id,
        severity,
        confidence,
        entry_path: path.to_owned(),
        explanation,
    }
}

fn nested_archive_name(path: &str) -> bool {
    [
        ".zip", ".jar", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ]
    .iter()
    .any(|suffix| path.to_ascii_lowercase().ends_with(suffix))
}

fn double_extension(path: &str) -> bool {
    let file = path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();
    let parts: Vec<_> = file.split('.').collect();
    parts.len() >= 3
        && [
            "pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt",
        ]
        .contains(&parts[parts.len() - 2])
        && ["exe", "dll", "scr", "com", "bat", "cmd", "ps1", "vbs", "js"]
            .contains(&parts[parts.len() - 1])
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
    use super::inspect_tar;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use proptest::prelude::*;
    use std::io::{Cursor, Write};

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

    fn synthetic_tar(name: &str, link: Option<&str>) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o644);
        if let Some(target) = link {
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_link_name(target).unwrap();
        } else {
            header.set_entry_type(tar::EntryType::Regular);
        }
        header.set_cksum();
        builder
            .append_data(&mut header, name, Cursor::new([]))
            .unwrap();
        builder.into_inner().unwrap()
    }

    fn patch_tar_name(mut data: Vec<u8>, name: &[u8]) -> Vec<u8> {
        data[..100].fill(0);
        data[..name.len()].copy_from_slice(name);
        data[148..156].fill(b' ');
        let checksum: u64 = data[..512].iter().map(|byte| u64::from(*byte)).sum();
        let encoded = format!("{checksum:06o}\0 ");
        data[148..156].copy_from_slice(encoded.as_bytes());
        data
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
                .findings
                .iter()
                .any(|finding| finding.rule_id == "archive.path_traversal"));
            assert!(result
                .warnings
                .iter()
                .any(|warning| warning.contains("encrypted")));
            assert!(result
                .findings
                .iter()
                .any(|finding| finding.rule_id == "archive.encrypted_entry"));
        }
    }

    #[test]
    fn detects_zip_bomb_ratio_nested_archive_and_double_extension_names() {
        let bomb = inspect(&synthetic_zip(b"bundle.zip", 0, 1, 2_000));
        assert!(bomb
            .findings
            .iter()
            .any(|finding| finding.rule_id == "archive.compression_ratio"));
        assert!(bomb
            .findings
            .iter()
            .any(|finding| finding.rule_id == "archive.nested_archive"));
        let double = inspect(&synthetic_zip(b"report.pdf.exe", 0, 5, 5));
        assert!(double
            .findings
            .iter()
            .any(|finding| finding.rule_id == "archive.double_extension"));
    }

    #[test]
    fn rejects_truncated_and_oversized_inputs_cleanly() {
        assert_eq!(inspect(b"PK\x05\x06").member_count, None);
        let too_large = vec![0; 64 * 1024 * 1024 + 1];
        assert!(inspect(&too_large).warnings[0].contains("64 MiB"));
        let declared_bomb = synthetic_zip(b"large.bin", 0, 1, 64 * 1024 * 1024 + 1);
        assert!(inspect(&declared_bomb).warnings[0].contains("declared uncompressed size"));
    }

    #[test]
    fn lists_tar_and_targz_headers_and_detects_hostile_names() {
        let tar_bytes = patch_tar_name(synthetic_tar("safe", None), b"../escape/report.pdf.exe");
        let plain = inspect_tar(&tar_bytes, false);
        assert_eq!(plain.member_count, Some(1));
        assert_eq!(plain.names, ["../escape/report.pdf.exe"]);
        assert!(plain
            .findings
            .iter()
            .any(|item| item.rule_id == "archive.path_traversal"));
        assert!(plain
            .findings
            .iter()
            .any(|item| item.rule_id == "archive.double_extension"));

        let encoder = GzEncoder::new(Vec::new(), Compression::fast());
        let mut encoder = encoder;
        encoder.write_all(&synthetic_tar("safe.txt", None)).unwrap();
        let gz_bytes = encoder.finish().unwrap();
        assert_eq!(inspect_tar(&gz_bytes, true).names, ["safe.txt"]);

        let linked = inspect_tar(&synthetic_tar("link", Some("../../outside")), false);
        assert!(linked
            .findings
            .iter()
            .any(|item| item.rule_id == "archive.link_escape"));
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 100, max_shrink_iters: 1_000, .. ProptestConfig::default() })]

        #[test]
        fn zip_parser_never_panics_on_bounded_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..65_536)) {
            let result = inspect(&data);
            prop_assert!(result.names.len() <= 1_000);
            prop_assert!(result.findings.len() <= 2_000);
        }

        #[test]
        fn tar_parser_never_panics_on_bounded_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..65_536)) {
            let result = inspect_tar(&data, false);
            prop_assert!(result.names.len() <= 1_000);
            prop_assert!(result.findings.len() <= 2_000);
        }
    }
}
