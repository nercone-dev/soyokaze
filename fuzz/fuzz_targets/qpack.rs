#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../tests/harness/mod.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::qpack::check(data);
});
