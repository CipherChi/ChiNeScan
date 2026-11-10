#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    chinescan_engine::fuzz_tar_metadata(data, false);
    chinescan_engine::fuzz_tar_metadata(data, true);
});
