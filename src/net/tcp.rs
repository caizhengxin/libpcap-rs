use jppe::{BorrowByteDecode, BorrowByteEncode};


#[derive(Debug, Default, PartialEq, Eq, BorrowByteEncode, BorrowByteDecode)]
pub struct TcpHeader<'a> {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    #[jppe(bits_start=0xf000, value_decode="header_length * 4", value_encode="header_length / 4", untake)]
    pub header_length: u16,
    #[jppe(bits=0x0fff)]
    pub flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    #[jppe(length="header_length - 20")]
    pub options: &'a [u8],
}