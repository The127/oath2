use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::{Into, TryFrom};
use std::io::{Cursor};

use super::flow_match::Match;

use super::super::err::*;

#[derive(Debug, PartialEq, Clone)]
pub struct FlowRemoved {
    cookie: u64,
    
    priority: u16,
    reason: FlowRemovedReason,
    table_id: u8,

    duration_sec: u32,
    duration_nsec: u32,
    
    idle_timeout: u16,
    hard_timeout: u16,

    packet_count: u64,
    byte_count: u64,

    mmatch: Match,
}

impl<'a> TryFrom<&'a [u8]> for FlowRemoved {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let cookie = cursor.read_u64::<BigEndian>().unwrap();
        let priority = cursor.read_u16::<BigEndian>().unwrap();
        let reason_raw = cursor.read_u8().unwrap();
        let reason = FlowRemovedReason::from_u8(reason_raw).ok_or::<Error>(
            ErrorKind::UnknownValue(reason_raw as u64, stringify!(FlowRemovedReason)).into(),
        )?;
        let table_id = cursor.read_u8().unwrap();
        let duration_sec = cursor.read_u32::<BigEndian>().unwrap();
        let duration_nsec = cursor.read_u32::<BigEndian>().unwrap();
        let idle_timeout = cursor.read_u16::<BigEndian>().unwrap();
        let hard_timeout = cursor.read_u16::<BigEndian>().unwrap();
        let packet_count = cursor.read_u64::<BigEndian>().unwrap();
        let byte_count = cursor.read_u64::<BigEndian>().unwrap();

        let mmatch_slice_len = Match::read_len(&mut cursor)?;
        let mmatch_slice =
            &bytes[cursor.position() as usize..cursor.position() as usize + mmatch_slice_len];
        let mmatch = Match::try_from(mmatch_slice)?;

        Ok(FlowRemoved {
            cookie: cookie,
            
            priority: priority,
            reason: reason,
            table_id: table_id,

            duration_sec: duration_sec,
            duration_nsec: duration_nsec,
            
            idle_timeout: idle_timeout,
            hard_timeout: hard_timeout,

            packet_count: packet_count,
            byte_count: byte_count,

            mmatch: mmatch,
        })
    }
}

impl Into<Vec<u8>> for FlowRemoved {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u64::<BigEndian>(self.cookie).unwrap();
        res.write_u16::<BigEndian>(self.priority).unwrap();
        res.write_u8(self.reason.to_u8().unwrap()).unwrap();
        res.write_u8(self.table_id).unwrap();
        res.write_u32::<BigEndian>(self.duration_sec).unwrap();
        res.write_u32::<BigEndian>(self.duration_nsec).unwrap();
        res.write_u16::<BigEndian>(self.idle_timeout).unwrap();
        res.write_u16::<BigEndian>(self.hard_timeout).unwrap();
        res.write_u64::<BigEndian>(self.packet_count).unwrap();
        res.write_u64::<BigEndian>(self.byte_count).unwrap();
        res.extend_from_slice(&Into::<Vec<u8>>::into(self.mmatch)[..]);
        res
    }
}

/// Why was this flow removed? 
#[derive(Primitive, PartialEq, Debug, Clone)]
pub enum FlowRemovedReason {
    /// Flow idle time exceeded idle_timeout. 
    IdleTimeout = 0, 
    /// Time exceeded hard_timeout. 
    HardTimeout = 1, 
    /// Evicted by a DELETE flow mod. 
    Delete = 2, 
    /// Group was removed. 
    GroupDelete = 3, 
}
