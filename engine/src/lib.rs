#![forbid(unsafe_code)]

mod limits;
mod magic;
mod redact;
mod zipmeta;

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
    Ok(())
}
