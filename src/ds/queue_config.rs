use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::convert::{TryFrom, Into};
use std::io::{Cursor, Seek, SeekFrom};

use super::ports::PortNumber;
use super::packet_queue;

use super::super::err::*;

#[derive(Debug)]
pub struct QueueGetConfigRequest {
    pub port: PortNumber,
    // pad 4 bytes
}

impl Into<Vec<u8>> for QueueGetConfigRequest{
    fn into(self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.write_u32::<BigEndian>(self.port.into()).unwrap();
        // pad 4 bytes
        vec.write_u32::<BigEndian>(0).unwrap();
        vec
    }
}

impl<'a> TryFrom<&'a [u8]> for QueueGetConfigRequest{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(QueueGetConfigRequest{
            port: PortNumber::try_from(cursor.read_u32::<BigEndian>().unwrap())?,
        })
    }
}

unsafe impl Send for QueueGetConfigRequest {}

#[derive(Debug)]
pub struct QueueGetConfigReply {
    pub port: PortNumber,
    // pad 4 bytes
    queues: Vec<packet_queue::PacketQueue>,
}

impl Into<Vec<u8>> for QueueGetConfigReply{
    fn into(self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.write_u32::<BigEndian>(self.port.into()).unwrap();
        // pad 4 bytes
        vec.write_u32::<BigEndian>(0).unwrap();
        for queue in self.queues {
            vec.extend_from_slice(&Into::<Vec<u8>>::into(queue)[..]);
        }
        vec
    }
}

impl<'a> TryFrom<&'a [u8]> for QueueGetConfigReply{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let port = PortNumber::try_from(cursor.read_u32::<BigEndian>().unwrap())?;
        cursor.seek(SeekFrom::Current(4)).unwrap();

        let mut queues = Vec::new();
        let mut bytes_left = bytes.len() - 8;
        while bytes_left > 0 {
            let queue_len = packet_queue::PacketQueue::read_len(&mut cursor)?;
            let queue_slice = &bytes[cursor.position() as usize..cursor.position() as usize + queue_len];
            let queue = packet_queue::PacketQueue::try_from(queue_slice)?;
            queues.push(queue);
            bytes_left -= queue_len;
            cursor.seek(SeekFrom::Current(queue_len as i64)).unwrap();
        }

        Ok(QueueGetConfigReply{
            port: port,
            queues: queues,
        })
    }
}

unsafe impl Send for QueueGetConfigReply {}