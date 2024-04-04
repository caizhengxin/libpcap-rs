pub mod ethernet;
pub mod ipv4;
pub mod tcp;
pub mod udp;
pub mod checksum;

use std::net::IpAddr;

pub use tcp::TcpHeader;
pub use udp::UdpHeader;
pub use ipv4::Ipv4Header;
pub use ethernet::EthernetHeader;
pub use checksum::CheckSum;

use jppe::{BorrowByteDecode, BorrowByteEncode};


#[derive(Debug, PartialEq, Eq, BorrowByteEncode, BorrowByteDecode)]
pub struct ChecksumLayer<'a> {
    pub layer12: EthernetHeader<'a>,
    #[jppe(branch="layer12.r#type")]
    pub layer3: Layer3<'a>,
    // #[jppe(branch="layer3.get_protocol().unwrap_or_default()")]
    // pub layer4: Layer4<'a>,
    pub remain: &'a [u8],
}


impl<'a> ChecksumLayer<'a> {
    pub fn checksum(&self) -> Option<u16> {
        if let Some(src) = self.layer3.get_src_vec() {
            if let Some(dst) = self.layer3.get_dst_vec() {
                if let Some(protocol) = self.layer3.get_protocol() {
                    return Some(CheckSum::new_tcp_or_udp(&src, &dst, protocol, self.remain).checksum());
                }
            }
        }

        None
    }

    pub fn verify(&self) -> bool {
        if let Some(src) = self.layer3.get_src_vec() {
            if let Some(dst) = self.layer3.get_dst_vec() {
                if let Some(protocol) = self.layer3.get_protocol() {
                    if CheckSum::new_tcp_or_udp(&src, &dst, protocol, self.remain).verify() {
                        return true;
                    }
                }
            }
        }

        false
    }
}


#[derive(Debug, PartialEq, Eq, BorrowByteEncode, BorrowByteDecode)]
pub enum Layer3<'a> {
    #[jppe(branch_value=0x0800)]
    Ipv4(Ipv4Header<'a>),
    #[jppe(branch_default)]
    Unknown,
}


impl<'a> Layer3<'a> {
    pub fn get_protocol(&self) -> Option<u8> {
        match self {
            Self::Ipv4(v) => Some(v.protocol),
            _ => None,
        }
    }

    pub fn get_src(&self) -> Option<IpAddr> {
        match self {
            Self::Ipv4(v) => Some(IpAddr::V4(v.src)),
            _ => None,
        }
    }

    pub fn get_dst(&self) -> Option<IpAddr> {
        match self {
            Self::Ipv4(v) => Some(IpAddr::V4(v.dst)),
            _ => None,
        }
    }

    pub fn get_src_vec(&self) -> Option<Vec<u8>> {
        match self {
            Self::Ipv4(v) => Some(v.src.octets().to_vec()),
            _ => None,
        }
    }

    pub fn get_dst_vec(&self) -> Option<Vec<u8>> {
        match self {
            Self::Ipv4(v) => Some(v.dst.octets().to_vec()),
            _ => None,
        }
    }
}


#[derive(Debug, PartialEq, Eq, BorrowByteEncode, BorrowByteDecode)]
pub enum Layer4<'a> {
    #[jppe(branch_value=6)]
    Tcp(TcpHeader<'a>),
    #[jppe(branch_value=17)]
    Udp(UdpHeader<'a>),
    #[jppe(branch_default)]
    Unknown,
}


impl<'a> Layer4<'a> {
    pub fn get_sport(&self) -> Option<u16> {
        match self {
            Self::Tcp(v) => Some(v.sport),
            Self::Udp(v) => Some(v.sport),
            _ => None,
        }
    }

    pub fn get_dport(&self) -> Option<u16> {
        match self {
            Self::Tcp(v) => Some(v.dport),
            Self::Udp(v) => Some(v.dport),
            _ => None,
        }
    }

    pub fn get_tcp_flags(&self) -> Option<u16> {
        match self {
            Self::Tcp(v) => Some(v.flags),
            _ => None,
        }
    }
}


#[derive(Debug, PartialEq, Eq, BorrowByteEncode, BorrowByteDecode)]
pub struct Layer<'a> {
    pub layer12: EthernetHeader<'a>,
    #[jppe(branch="layer12.r#type")]
    pub layer3: Layer3<'a>,
    #[jppe(branch="layer3.get_protocol().unwrap_or_default()")]
    pub layer4: Layer4<'a>,
    pub remain: &'a [u8],
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layer_encode_and_decode() {
        let mut input = b"\x00\xc0\x9f\x32\x41\x8c\x00\xe0\x18\xb1\x0c\xad\x08\x00\x45\x00\
        \x00\x38\x00\x00\x40\x00\x40\x11\x65\x47\xc0\xa8\xaa\x08\xc0\xa8\
        \xaa\x14\x80\x1b\x00\x35\x00\x24\x85\xef\x10\x32\x01\x00\x00\x01\
        \x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\
        \x6d\x00\x00\x10\x00\x01".to_vec();

        let (_, value) = jppe::decode_borrow::<ChecksumLayer<'_>>(&input).unwrap();
        assert_eq!(value.verify(), false);

        if let Some(protocol) = value.layer3.get_protocol() {
            if let Some(checksum) = value.checksum() {
                let checksum_array = checksum.to_be_bytes();

                if protocol == 17 {
                    input[14 + 20 + 6] = checksum_array[0];
                    input[14 + 20 + 7] = checksum_array[1];
                }
                else if protocol == 6 {
                    input[14 + 20 + 16] = checksum_array[0];
                    input[14 + 20 + 17] = checksum_array[1];
                }    
            }
        }

        let (_, value) = jppe::decode_borrow::<ChecksumLayer<'_>>(&input).unwrap();
        assert_eq!(value.verify(), true);
    }
}