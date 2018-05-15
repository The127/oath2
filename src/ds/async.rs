use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::convert::{Into, TryFrom};
use std::io::Cursor;

use super::super::err::*;

#[derive(Debug)]
pub struct Async {
    pub packet_in_mask_1: u32,
    pub packet_in_mask_2: u32,
    pub port_status_mask_1: u32,
    pub port_status_mask_2: u32,
    pub flow_removed_mask_1: u32,
    pub flow_removed_mask_2: u32,
}

unsafe impl Send for Async {}

impl<'a> TryFrom<&'a [u8]> for Async {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(Async {
            packet_in_mask_1: cursor.read_u32::<BigEndian>().unwrap(),
            packet_in_mask_2: cursor.read_u32::<BigEndian>().unwrap(),
            port_status_mask_1: cursor.read_u32::<BigEndian>().unwrap(),
            port_status_mask_2: cursor.read_u32::<BigEndian>().unwrap(),
            flow_removed_mask_1: cursor.read_u32::<BigEndian>().unwrap(),
            flow_removed_mask_2: cursor.read_u32::<BigEndian>().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for Async {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(self.packet_in_mask_1).unwrap();
        res.write_u32::<BigEndian>(self.packet_in_mask_2).unwrap();
        res.write_u32::<BigEndian>(self.port_status_mask_1).unwrap();
        res.write_u32::<BigEndian>(self.port_status_mask_2).unwrap();
        res.write_u32::<BigEndian>(self.flow_removed_mask_1)
            .unwrap();
        res.write_u32::<BigEndian>(self.flow_removed_mask_2)
            .unwrap();
        res
    }
}
