#[macro_export]
macro_rules! make_cstr {
    ($value:expr) => {
        unsafe { CStr::from_ptr($value).to_string_lossy().to_string() }
    };
}
