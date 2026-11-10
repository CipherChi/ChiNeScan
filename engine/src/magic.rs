//! Small, conservative magic-byte table; labels describe formats, not trust.

pub fn identify(data: &[u8], extension: &str) -> (&'static str, bool, bool) {
    let (kind, expected, executable) = if data.starts_with(b"MZ") {
        (
            "PE executable (Windows)",
            &["exe", "dll", "sys", "ocx", "scr"][..],
            true,
        )
    } else if data.starts_with(b"\x7fELF") {
        (
            "ELF executable (Linux/Unix)",
            &["elf", "so", "bin"][..],
            true,
        )
    } else if data.starts_with(b"%PDF-") {
        ("PDF document", &["pdf"][..], false)
    } else if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        (
            "ZIP archive",
            &["zip", "jar", "docx", "xlsx", "pptx"][..],
            false,
        )
    } else if data.starts_with(b"\x1f\x8b") {
        ("GZIP compressed data", &["gz", "tgz"][..], false)
    } else if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        ("PNG image", &["png"][..], false)
    } else if data.starts_with(b"\xff\xd8\xff") {
        ("JPEG image", &["jpg", "jpeg"][..], false)
    } else if data.get(257..262) == Some(b"ustar") {
        ("TAR archive", &["tar", "tgz"][..], false)
    } else {
        return ("Unknown or unrecognized", false, false);
    };
    let ext = extension.trim_start_matches('.').to_ascii_lowercase();
    (kind, !expected.contains(&ext.as_str()), executable)
}

#[cfg(test)]
mod tests {
    use super::identify;

    #[test]
    fn recognizes_common_inert_signatures_and_extension_mismatches() {
        assert_eq!(
            identify(b"MZ\0\0", "pdf"),
            ("PE executable (Windows)", true, true)
        );
        assert_eq!(identify(b"%PDF-1.7", "pdf"), ("PDF document", false, false));
        assert_eq!(
            identify(b"\x89PNG\r\n\x1a\n", "exe"),
            ("PNG image", true, false)
        );
        assert_eq!(
            identify(b"plain text", "txt"),
            ("Unknown or unrecognized", false, false)
        );
    }
}
