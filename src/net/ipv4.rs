use std::net::Ipv4Addr;
use jppe::{BorrowByteDecode, BorrowByteEncode};


#[derive(Debug, PartialEq, Eq, BorrowByteEncode, BorrowByteDecode)]
pub struct Ipv4Header<'a> {
    #[jppe(bits_start=0xf0, untake)]
    pub version: u8,
    #[jppe(bits=0x0f, value_decode="header_length << 2", value_encode="header_length >> 2")]
    pub header_length: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    #[jppe(bits_start=0xe000, untake)]
    pub flags: u16,
    #[jppe(bits=0x1fff)]
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    #[jppe(length="header_length - 20")]
    pub options: &'a [u8],
}
