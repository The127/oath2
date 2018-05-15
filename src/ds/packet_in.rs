use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::{TryFrom, Into};
use std::io::{Cursor, Seek, SeekFrom};

use super::flow_match::Match;

use super::super::err::*;

#[derive(Debug, PartialEq, Clone)]
pub struct PacketIn {
    pub buffer_id: u32,
    pub total_len: u16,
    pub reason: InReason,
    pub table_id: u8,
    pub cookie: u64,
    pub mmatch: Match,
    //pad 2 bytes
    pub ethernet_frame: Vec<u8>,
}

unsafe impl Send for PacketIn {}

impl<'a> TryFrom<&'a [u8]> for PacketIn {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let buffer_id = cursor.read_u32::<BigEndian>().unwrap();
        let total_len = cursor.read_u16::<BigEndian>().unwrap();
        let reason_raw = cursor.read_u8().unwrap();
        let reason = InReason::from_u8(reason_raw)
            .ok_or::<Error>(ErrorKind::UnknownValue(reason_raw as u64, stringify!(InReason)).into())?;
        let table_id = cursor.read_u8().unwrap();
        let cookie = cursor.read_u64::<BigEndian>().unwrap();

        let mmatch_slice_len = Match::read_len(&mut cursor)?;
        let mmatch_slice = &bytes[cursor.position() as usize..cursor.position() as usize + mmatch_slice_len];
        let mmatch = Match::try_from(mmatch_slice)?;
        cursor.seek(SeekFrom::Current(mmatch_slice_len as i64)).unwrap();

        cursor.seek(SeekFrom::Current(2)).unwrap();//2 bytes padding
        let eth_slice = &bytes[cursor.position() as usize..];
        let ethernet_frame = Vec::from(eth_slice);

        Ok(PacketIn{
            buffer_id: buffer_id,
            total_len: total_len, 
            reason: reason,
            table_id: table_id, 
            cookie: cookie, 
            mmatch: mmatch,
            ethernet_frame: ethernet_frame,
        })
    }
}

impl Into<Vec<u8>> for PacketIn {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(self.buffer_id).unwrap();
        res.write_u16::<BigEndian>(self.total_len).unwrap();
        res.write_u8(self.reason.to_u8().unwrap()).unwrap();
        res.write_u8(self.table_id).unwrap();
        res.write_u64::<BigEndian>(self.cookie).unwrap();
        res.extend_from_slice(&Into::<Vec<u8>>::into(self.mmatch)[..]);
        res.extend_from_slice(&self.ethernet_frame[..]);
        res
    }
}

/// Why is this packet being sent to the controller? 
#[derive(Primitive, PartialEq, Debug, Clone)]
pub enum InReason {
    /// No matching flow (table-miss flow entry). 
    NoMatch = 0, 
    /// Action explicitly output to controller. 
    Action = 1, 
    /// Packet has invalid TTL 
    InvalidTtl = 2, 
}
