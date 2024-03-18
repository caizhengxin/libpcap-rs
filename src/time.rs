use std::time::SystemTime;


#[inline]
pub fn now_timestamp() -> u64 {
    SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}
