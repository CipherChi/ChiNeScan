#![forbid(unsafe_code)]

mod limits;
mod magic;
mod redact;
mod zipmeta;

use ed25519_dalek::{Signer, Verifier};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

pub const ENGINE_API_VERSION: u32 = 1;
const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
const REGEX_CRATE_VERSION: &str = "1.11.3";
const GIL_RELEASE_THRESHOLD: usize = 64 * 1024;

/// Public fuzz harness surface; inputs remain bounded by the parsers themselves.
pub fn fuzz_zip_metadata(data: &[u8]) {
    let _ = zipmeta::inspect(data);
}

/// Public fuzz harness surface for TAR and TAR.GZ metadata parsing.
pub fn fuzz_tar_metadata(data: &[u8], compressed: bool) {
    let _ = zipmeta::inspect_tar(data, compressed);
}

#[pyfunction]
fn redact_text(py: Python<'_>, text: &str) -> String {
    if text.len() < GIL_RELEASE_THRESHOLD {
        return redact::redact_text(text);
    }
    let owned = text.to_owned();
    py.detach(move || redact::redact_text(&owned))
}

#[pyfunction]
fn engine_info(py: Python<'_>) -> PyResult<Py<PyDict>> {
    let info = PyDict::new(py);
    info.set_item("version", ENGINE_VERSION)?;
    info.set_item("api_version", ENGINE_API_VERSION)?;
    info.set_item("regex_crate", REGEX_CRATE_VERSION)?;
    Ok(info.unbind())
}

#[pyfunction]
fn inspect_zip_metadata(py: Python<'_>, data: &[u8]) -> PyResult<Py<PyDict>> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| zipmeta::inspect(data)))
        .unwrap_or_else(|_| zipmeta::Inspection::failed("ZIP metadata parser failed safely."));
    inspection_to_py(py, result)
}

#[pyfunction]
fn inspect_tar_metadata(py: Python<'_>, data: &[u8], compressed: bool) -> PyResult<Py<PyDict>> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        zipmeta::inspect_tar(data, compressed)
    }))
    .unwrap_or_else(|_| zipmeta::Inspection::failed("TAR metadata parser failed safely."));
    inspection_to_py(py, result)
}

#[pyfunction]
fn identify_file_type(py: Python<'_>, data: &[u8], extension: &str) -> PyResult<Py<PyDict>> {
    let (file_type, mismatch, executable) = magic::identify(data, extension);
    let output = PyDict::new(py);
    output.set_item("file_type", file_type)?;
    output.set_item("extension_mismatch", mismatch)?;
    output.set_item("executable_signature", executable)?;
    Ok(output.unbind())
}

#[pyfunction]
fn render_report_json(request: &str) -> PyResult<String> {
    if request.len() > 16 * 1024 * 1024 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "report request limit exceeded",
        ));
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let request: chinescan_reporter::ReportRequest = serde_json::from_str(request)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid report request"))?;
        let response = chinescan_reporter::render(&request)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("report rendering failed"))?;
        Ok(response.content)
    }))
    .unwrap_or_else(|_| {
        Err(pyo3::exceptions::PyRuntimeError::new_err(
            "report worker panic contained",
        ))
    })
}

#[pyfunction]
fn sign_report_detached(content: &[u8], private_seed: &[u8]) -> PyResult<String> {
    if content.len() > 3 * 1024 * 1024 || private_seed.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "invalid signature request",
        ));
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let seed: &[u8; 32] = private_seed
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid signing key"))?;
        let key = ed25519_dalek::SigningKey::from_bytes(seed);
        let sig = key.sign(content);
        Ok(hex_encode(sig.to_bytes()))
    }))
    .unwrap_or_else(|_| {
        Err(pyo3::exceptions::PyRuntimeError::new_err(
            "signature operation failed safely",
        ))
    })
}

#[pyfunction]
fn verify_report_detached(content: &[u8], signature: &[u8], public_key: &[u8]) -> PyResult<bool> {
    if content.len() > 3 * 1024 * 1024 || signature.len() != 64 || public_key.len() != 32 {
        return Ok(false);
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let key_bytes: &[u8; 32] = public_key
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid key"))?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(key_bytes)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid public key"))?;
        let sig = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid signature"))?;
        Ok(key.verify(content, &sig).is_ok())
    }))
    .unwrap_or(Ok(false))
}

#[pyfunction]
fn report_public_key(private_seed: &[u8]) -> PyResult<Vec<u8>> {
    let seed: &[u8; 32] = private_seed
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid signing key"))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
        .to_vec())
}

#[pyfunction]
fn sign_report_worker(request: &str) -> PyResult<String> {
    #[derive(serde::Deserialize)]
    struct Input {
        content: String,
        private_seed_hex: String,
    }
    let input: Input = serde_json::from_str(request)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid signature request"))?;
    let seed = decode_hex(&input.private_seed_hex)
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("invalid signing key"))?;
    sign_report_detached(input.content.as_bytes(), &seed)
}

#[pyfunction]
fn verify_report_worker(request: &str) -> PyResult<bool> {
    #[derive(serde::Deserialize)]
    struct Input {
        content: String,
        signature_hex: String,
        public_key_hex: String,
    }
    let input: Input = serde_json::from_str(request)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid verification request"))?;
    let sig = decode_hex(&input.signature_hex).unwrap_or_default();
    let key = decode_hex(&input.public_key_hex).unwrap_or_default();
    verify_report_detached(input.content.as_bytes(), &sig, &key)
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) || value.len() > 128 || !value.is_ascii() {
        return None;
    }
    value
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(text, 16).ok()
        })
        .collect()
}

fn hex_encode(bytes: [u8; 64]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn inspection_to_py(py: Python<'_>, result: zipmeta::Inspection) -> PyResult<Py<PyDict>> {
    let output = PyDict::new(py);
    let parse_failed = result.member_count.is_none();
    output.set_item("member_count", result.member_count)?;
    output.set_item("names", result.names)?;
    output.set_item("warnings", result.warnings)?;
    output.set_item(
        "error",
        if parse_failed {
            Some("parser_rejected")
        } else {
            None
        },
    )?;
    let findings = PyList::empty(py);
    for finding in result.findings {
        let item = PyDict::new(py);
        item.set_item("id", finding.id)?;
        item.set_item("rule_id", finding.rule_id)?;
        item.set_item("severity", finding.severity)?;
        item.set_item("confidence", finding.confidence)?;
        item.set_item("entry_path", finding.entry_path)?;
        item.set_item("explanation", finding.explanation)?;
        findings.append(item)?;
    }
    output.set_item("findings", findings)?;
    Ok(output.unbind())
}

#[pymodule]
fn chinescan_engine(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("__version__", ENGINE_VERSION)?;
    module.add("ENGINE_API_VERSION", ENGINE_API_VERSION)?;
    module.add_function(wrap_pyfunction!(redact_text, module)?)?;
    module.add_function(wrap_pyfunction!(engine_info, module)?)?;
    module.add_function(wrap_pyfunction!(inspect_zip_metadata, module)?)?;
    module.add_function(wrap_pyfunction!(inspect_tar_metadata, module)?)?;
    module.add_function(wrap_pyfunction!(identify_file_type, module)?)?;
    module.add_function(wrap_pyfunction!(render_report_json, module)?)?;
    module.add_function(wrap_pyfunction!(sign_report_detached, module)?)?;
    module.add_function(wrap_pyfunction!(verify_report_detached, module)?)?;
    module.add_function(wrap_pyfunction!(report_public_key, module)?)?;
    module.add_function(wrap_pyfunction!(sign_report_worker, module)?)?;
    module.add_function(wrap_pyfunction!(verify_report_worker, module)?)?;
    Ok(())
}

#[cfg(test)]
mod report_signature_tests {
    use ed25519_dalek::{Signer, Verifier};

    #[test]
    fn detached_signature_rejects_tampering_and_wrong_keys() {
        let seed_a = [7_u8; 32];
        let seed_b = [8_u8; 32];
        let content = b"local report content";
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_a);
        let signature = signing_key.sign(content);
        assert!(signing_key
            .verifying_key()
            .verify(content, &signature)
            .is_ok());
        assert!(signing_key
            .verifying_key()
            .verify(b"tampered report", &signature)
            .is_err());
        assert!(ed25519_dalek::SigningKey::from_bytes(&seed_b)
            .verifying_key()
            .verify(content, &signature)
            .is_err());
    }
}
