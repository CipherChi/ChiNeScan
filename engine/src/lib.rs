#![forbid(unsafe_code)]

mod limits;
mod redact;
mod zipmeta;

use pyo3::prelude::*;
use pyo3::types::PyDict;

pub const ENGINE_API_VERSION: u32 = 1;
const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
const REGEX_CRATE_VERSION: &str = "1.11.3";
const GIL_RELEASE_THRESHOLD: usize = 64 * 1024;

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
    let output = PyDict::new(py);
    output.set_item("member_count", result.member_count)?;
    output.set_item("names", result.names)?;
    output.set_item("warnings", result.warnings)?;
    Ok(output.unbind())
}

#[pymodule]
fn chinescan_engine(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("__version__", ENGINE_VERSION)?;
    module.add("ENGINE_API_VERSION", ENGINE_API_VERSION)?;
    module.add_function(wrap_pyfunction!(redact_text, module)?)?;
    module.add_function(wrap_pyfunction!(engine_info, module)?)?;
    module.add_function(wrap_pyfunction!(inspect_zip_metadata, module)?)?;
    Ok(())
}
