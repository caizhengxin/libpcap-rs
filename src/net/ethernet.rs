use std::marker::PhantomData;
use jppe::{BorrowByteDecode, BorrowByteEncode};
use jppe::prelude::MacAddress;


#[derive(Debug, PartialEq, Eq, BorrowByteEncode, BorrowByteDecode)]
pub struct EthernetHeader<'a> {
    pub smac: MacAddress,
    pub dmac: MacAddress,
    pub r#type: u16,
    _mark: PhantomData<&'a ()>,
}
