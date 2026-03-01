fn go() {
    // ruleid: rust.unsafe-block
    unsafe {
        let p: *const u8 = std::ptr::null();
        let _ = *p;
    }
}
