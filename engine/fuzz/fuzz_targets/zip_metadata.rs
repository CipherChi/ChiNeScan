#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| chinescan_engine::fuzz_zip_metadata(data));
