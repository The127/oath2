use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::convert::{Into, TryFrom};
use std::io::{Cursor, Seek, SeekFrom};

use super::actions::{ActionHeader, calc_actions_len};
use super::ports::PortNumber;

use super::super::err::*;

pub const PACKET_OUT_LEN: usize = 16;

#[derive(Debug, PartialEq, Clone)]
pub struct PacketOut {
    pub buffer_id: u32,
    pub in_port: PortNumber,
    pub actions_len: u16,
    //pad 6 bytes
    pub actions: Vec<ActionHeader>,
    pub data: Vec<u8>,
}

impl PacketOut {
    pub fn new(buffer_id: u32, in_port: PortNumber, actions: Vec<ActionHeader>, data: Vec<u8>) -> Self {
        PacketOut{
            buffer_id: buffer_id,
            in_port: in_port,
            actions_len: calc_actions_len(&actions),
            actions: actions,
            data: data,
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for PacketOut {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let buffer_id = cursor.read_u32::<BigEndian>().unwrap();
        let in_port = PortNumber::try_from(cursor.read_u32::<BigEndian>().unwrap())?;
        let actions_len = cursor.read_u16::<BigEndian>().unwrap();
        cursor.seek(SeekFrom::Start(8)).unwrap();

        let mut actions = Vec::new();
        let mut bytes_remaining = actions_len as usize;
        while bytes_remaining > 0 {
            let action_len = ActionHeader::read_len(&mut cursor)?;
            let action_slice =
                &bytes[cursor.position() as usize..cursor.position() as usize + action_len];
            let action = ActionHeader::try_from(action_slice)?;
            actions.push(action);
            bytes_remaining -= action_len;
            cursor.seek(SeekFrom::Current(action_len as i64)).unwrap();
        }

        let data = Vec::from(&bytes[cursor.position() as usize..]);

        Ok(PacketOut {
            buffer_id: buffer_id,
            in_port: in_port,
            actions_len: actions_len,
            actions: actions,
            data: data,
        })
    }
}

impl Into<Vec<u8>> for PacketOut {
    fn into(self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.write_u32::<BigEndian>(self.buffer_id).unwrap();
        vec.write_u32::<BigEndian>(self.in_port.into()).unwrap();
        vec.write_u16::<BigEndian>(self.actions_len).unwrap();
        //pad 6 bytes
        vec.write_u32::<BigEndian>(0).unwrap();
        vec.write_u16::<BigEndian>(0).unwrap();
        for action in self.actions {
            vec.extend_from_slice(&Into::<Vec<u8>>::into(action)[..]);
        }
        vec.extend_from_slice(&self.data[..]);
        vec
    }
}
