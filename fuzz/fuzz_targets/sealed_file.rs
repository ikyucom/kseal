//! A sealed file is the one input kseal reads from wherever it is stored, so
//! parsing it must never panic, and anything it accepts must read back the same
//! after writing it out again.
#![no_main]

use kseal::SealedFile;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(sealed) = SealedFile::from_json(text) else {
        return;
    };
    let _ = (sealed.schema(), sealed.kms().provider());
    let json = sealed.to_json().expect("a parsed file serializes");
    let again = SealedFile::from_json(&json).expect("a written file parses");
    assert_eq!(again.secret(), sealed.secret());
    assert_eq!(again.body_sha256(), sealed.body_sha256());
    assert_eq!(again.to_json().unwrap(), json);
});
