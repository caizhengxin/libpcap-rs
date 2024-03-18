use std::marker::PhantomData;
use jppe::{BorrowByteDecode, BorrowByteEncode};


#[derive(Debug, Default, PartialEq, Eq, BorrowByteEncode, BorrowByteDecode)]
pub struct UdpHeader<'a> {
    pub sport: u16,
    pub dport: u16,
    pub length: u16,
    pub checksum: u16,
    _mark: PhantomData<&'a ()>,
}