use libpcap_rs::{Sniff, PResult};


fn _test_libpcap_sniff() -> PResult<()> {
    let _sniff = Sniff::open("lo")?
        .with_filter("port 80")?
        .with_snaplen(65535)
        .with_immediate_mode(1)
        .with_timeout(0);

    Ok(())
}


#[test]
fn test_libpcap_sniff() {
    assert_eq!(_test_libpcap_sniff().is_ok(), true);
}