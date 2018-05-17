use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::convert::{Into, TryFrom};
use std::io::Cursor;

use super::super::err::*;

#[derive(Debug, PartialEq, Clone)]
pub struct SwitchConfig {
    pub flags: ConfigFlags,
    pub miss_send_len: u16,
    // no padding, since there are no data after this
}

impl<'a> TryFrom<&'a [u8]> for SwitchConfig {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let flags = ConfigFlags::from_bits(cursor.read_u16::<BigEndian>().unwrap()).unwrap();
        let miss_send_len = cursor.read_u16::<BigEndian>().unwrap();
        Ok(SwitchConfig {
            flags: flags,
            miss_send_len: miss_send_len,
        })
    }
}

impl Into<Vec<u8>> for SwitchConfig {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.flags.bits()).unwrap();
        res.write_u16::<BigEndian>(self.flags.bits()).unwrap();
        res
    }
}

bitflags!{
    /// Handling of IP fragments.
    pub struct ConfigFlags: u16 {
        /// No special handling for fragments.
        const FRAG_NORMAL = 0;
        /// Drop fragments.
        const FRAG_DROP = 1 << 0;
        /// Reassemble (only if OFPC_IP_REASM set).
        const FRAG_REASM = 1 << 1;
        const FRAG_MASK = 3;
    }
}
