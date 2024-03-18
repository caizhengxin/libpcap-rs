#[derive(Debug)]
pub struct CheckSum<'a> {
    pub src_ip: &'a [u8],
    pub dst_ip: &'a [u8],
    pub protocol: u8,
    pub input: &'a [u8],
}


/// CheckSum
impl<'a> CheckSum<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            src_ip: &[],
            dst_ip: &[],
            protocol: 0,
            input
        }
    }

    pub fn new_tcp_or_udp(src_ip: &'a [u8], dst_ip: &'a [u8], protocol: u8, header_and_data: &'a [u8]) -> Self {
        Self {
            src_ip,
            dst_ip,
            protocol,
            input: header_and_data,
        }
    }

    pub fn checksum(&self) -> u16 {
        let mut first_input: &[u8] = &[];
        let mut last_input: &[u8] = &[];

        if self.protocol == 6 {
            first_input = self.input.get(..16).unwrap_or_else(|| &[]);
            last_input = self.input.get(18..).unwrap_or_else(|| &[]);
        }
        else if self.protocol == 17 {
            first_input = self.input.get(..6).unwrap_or_else(|| &[]);
            last_input = self.input.get(8..).unwrap_or_else(|| &[]);
        }

        let mut value = self.src_ip.array_chunks().map(|v: &[u8; 2]| u16::from_be_bytes(*v)).fold(0, |v1, v2| v1 + v2 as u32);
        value += self.dst_ip.array_chunks().map(|v: &[u8; 2]| u16::from_be_bytes(*v)).fold(0, |v1, v2| v1 + v2 as u32);
        // value = (0 << 8) | protcol
        value += self.protocol as u32;
        value += self.input.len() as u32;

        let length = last_input.len();

        if length % 2 == 0 {
            // Calculates the bytes before the checksum.
            value += first_input.array_chunks().map(|v: &[u8; 2]| u16::from_be_bytes(*v)).fold(0, |v1, v2| v1 + v2 as u32);
            // Calculates the bytes after the checksum.
            value += last_input.array_chunks().map(|v: &[u8; 2]| u16::from_be_bytes(*v)).fold(0, |v1, v2| v1 + v2 as u32);
        }
        else if let Some(v) = last_input.get(..length - 1) && let Some(v2) = last_input.last() {
            // Calculates the bytes before the checksum.
            value += first_input.array_chunks().map(|v: &[u8; 2]| u16::from_be_bytes(*v)).fold(0, |v1, v2| v1 + v2 as u32);
            // Calculates the bytes after the checksum.
            value += v.array_chunks().map(|v: &[u8; 2]| u16::from_be_bytes(*v)).fold(0, |v1, v2| v1 + v2 as u32);
            // Odd，full 0
            value += (((*v2 as u16) << 8) | 0) as u32;
        }

        while value >> 16 != 0 {
            value = (value >> 16) + (value & 0xffff)
        }

        !value as u16
    }

    pub fn verify(&self) -> bool {
        let length = self.input.len();

        let mut value = self.src_ip.array_chunks().map(|v: &[u8; 2]| u16::from_be_bytes(*v)).fold(0, |v1, v2| v1 + v2 as u32);
        value += self.dst_ip.array_chunks().map(|v: &[u8; 2]| u16::from_be_bytes(*v)).fold(0, |v1, v2| v1 + v2 as u32);
        // value = (0 << 8) | protcol
        value += self.protocol as u32;
        value += length as u32;

        if length % 2 == 0 {
            value += self.input.array_chunks().map(|v: &[u8; 2]| u16::from_be_bytes(*v)).fold(0, |v1, v2| v1 + v2 as u32);
        }
        else if let Some(v) = self.input.get(..length - 1) && let Some(v2) = self.input.last() {
            value += v.array_chunks().map(|v: &[u8; 2]| u16::from_be_bytes(*v)).fold(0, |v1, v2| v1 + v2 as u32);
            // Odd，full 0
            value += (((*v2 as u16) << 8) | 0) as u32;
        }

        while value >> 16 != 0 {
            value = (value >> 16) + (value & 0xffff)
        }

        !value as u16 == 0
    }
}


#[cfg(test)]
mod tests {
    use super::CheckSum;

    #[test]
    fn test_checksum_tcp() {
        // TCP even byte
        let input = b"\x0c\x0a\x01\xf6\x48\x3c\xbe\x86\x7a\x8a\xa5\x17\x50\x18\xfa\xf0\x62\x56\x00\x00\
                                \x00\x01\x00\x00\x00\x06\x0a\x01\x00\x00\x00\x01";

        let checksum = CheckSum::new_tcp_or_udp(
            &[0x0a, 0x00, 0x00, 0x09],
            &[0x0a, 0x00, 0x00, 0x03],
            0x06,
            input,
        );

        assert_eq!(checksum.verify(), true);
        assert_eq!(checksum.checksum(), 0x6256);
    }

    #[test]
    fn test_checksum_udp() {
        // UDP even byte (UDP Header + UDP Data)
        let input = b"\x04\x43\xba\xe3\x00\x5c\x0a\xb1\
            \x00\xf8\x04\x83\x00\x00\x00\x00\x00\x00\x00\x54\x00\x00\x00\x00\
            \x00\x00\x00\x00\x00\x00\x00\x00\x04\x4c\x00\x29\x00\x00\x01\x02\
            \x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x00\x50\x60\x70\x80\x10\
            \x23\x04\x05\x06\x07\x00\x80\x01\x02\x03\x04\x05\x06\x07\x08\x01\
            \x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08\
            \x01\x02\x03\x04";

        let checksum = CheckSum::new_tcp_or_udp(
            &[0xda, 0x55, 0x70, 0x8a],
            &[0x01, 0x02, 0x03, 0x04],
            17,
            input,
        );

        assert_eq!(checksum.verify(), true);
        assert_eq!(checksum.checksum(), 0x0ab1);
    }

    #[test]
    fn test_checksum_udp2() {
        // UDP odd byte (UDP Header + UDP Data)
        let input = b"\x48\x4b\x48\x4b\x00\x45\x5c\x93\
            \xfa\xce\x00\x2b\x00\x02\x17\x62\x00\x01\x8b\xd4\x54\x80\x01\x00\
            \x03\x01\x00\x00\x00\x00\x00\x53\x00\x00\x00\x00\x00\x00\x00\x00\
            \x00\x04\x00\x00\x00\x00\x00\x00\x89\x00\x80\x17\xe3\x00\x19\x00\
            \x21\x00\x00\x03\xe8\x00\x00\x00\x00\x00\x00\xc5\xf8";

        let checksum = CheckSum::new_tcp_or_udp(
            &[0x0a, 0x04, 0x00, 0x06],
            &[0x0a, 0x04, 0x00, 0x3e],
            17,
            input,
        );

        assert_eq!(checksum.verify(), true);
        assert_eq!(checksum.checksum(), 0x5c93);
    }
}