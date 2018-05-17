use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::{Into, TryFrom};
use std::io::{Cursor, Seek, SeekFrom};

use super::actions::ActionHeader;
use super::ports::PortNumber;

use super::super::err::*;
use std::path;

#[derive(Debug)]
pub struct GroupMod {
    command: GroupModCommand,
    ttype: GroupType,
    //pad 1 bytes
    group_id: u32,
    buckets: Vec<Bucket>,
}

impl<'a> TryFrom<&'a [u8]> for GroupMod {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let command_raw = cursor.read_u16::<BigEndian>().unwrap();
        let command = GroupModCommand::from_u16(command_raw).ok_or::<Error>(
            ErrorKind::UnknownValue(command_raw as u64, stringify!(GroupModCommand)).into(),
        )?;
        let ttype_raw = cursor.read_u8().unwrap();
        let ttype = GroupType::from_u8(ttype_raw).ok_or::<Error>(
            ErrorKind::UnknownValue(ttype_raw as u64, stringify!(GroupType)).into(),
        )?;
        let group_id = cursor.read_u32::<BigEndian>().unwrap();

        let mut buckets = Vec::new();
        let mut bytes_remaining = bytes.len() - 8;
        while bytes_remaining > 0 {
            let bucket_len = Bucket::read_len(&mut cursor)?;
            let bucket_slice =
                &bytes[cursor.position() as usize..cursor.position() as usize + bucket_len];
            let bucket = Bucket::try_from(bucket_slice)?;
            buckets.push(bucket);
            cursor.seek(SeekFrom::Current(bucket_len as i64)).unwrap();
            bytes_remaining -= bucket_len;
        }

        Ok(GroupMod {
            command: command,
            ttype: ttype,
            group_id: group_id,
            buckets: buckets,
        })
    }
}

impl Into<Vec<u8>> for GroupMod {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.command.to_u16().unwrap())
            .unwrap();
        res.write_u8(self.ttype.to_u8().unwrap()).unwrap();
        res.write_u8(0).unwrap(); // pad 1 byte
        res.write_u32::<BigEndian>(self.group_id).unwrap();
        for bucket in self.buckets {
            res.extend_from_slice(&Into::<Vec<u8>>::into(bucket)[..]);
        }
        res
    }
}

/// Group commands
#[derive(Primitive, PartialEq, Debug, Clone)]
pub enum GroupModCommand {
    /// New group.
    Add = 0,
    /// Modify all matching groups.
    Modify = 1,
    /// Delete all matching groups.
    Delete = 2,
}

/// Group types. Values in the range [128, 255] are reserved for experimental
/// use.
#[derive(Primitive, PartialEq, Debug, Clone)]
enum GroupType {
    /// All (multicast/broadcast) group.
    All = 0,
    /// Select group.
    Select = 1,
    /// Indirect group.
    Indirect = 2,
    /// Fast failover group.
    Ff = 3,
}

#[derive(Debug)]
pub struct Bucket {
    len: u16,
    weight: u16,
    watch_port: PortNumber,
    watch_group: u32,
    //pad 4 bytes
    actions: Vec<ActionHeader>,
}

impl Bucket {
    pub fn read_len(cursor: &mut Cursor<&[u8]>) -> Result<usize> {
        // read value and handle errors
        let len = match cursor.read_u16::<BigEndian>() {
            Ok(len) => len,
            Err(err) => {
                error!(
                    "Could not read packet queue len.{}{:?}{}{}",
                    path::MAIN_SEPARATOR,
                    cursor,
                    path::MAIN_SEPARATOR,
                    err
                );
                bail!(ErrorKind::CouldNotReadLength(0, stringify!(PacketQueue),))
            }
        };
        // go back to start
        cursor.seek(SeekFrom::Current(-2)).unwrap();
        Ok(len as usize)
    }
}

impl<'a> TryFrom<&'a [u8]> for Bucket {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);

        let len = cursor.read_u16::<BigEndian>().unwrap();
        let weight = cursor.read_u16::<BigEndian>().unwrap();
        let watch_port = PortNumber::try_from(cursor.read_u32::<BigEndian>().unwrap())?;
        let watch_group = cursor.read_u32::<BigEndian>().unwrap();
        //4 bytes padding
        cursor.seek(SeekFrom::Current(4)).unwrap();

        let mut actions = Vec::new();
        let mut bytes_remaining = (len - 16) as usize;
        while bytes_remaining > 0 {
            let action_len = ActionHeader::read_len(&mut cursor)?;
            let action_slice =
                &bytes[cursor.position() as usize..cursor.position() as usize + action_len];
            let action = ActionHeader::try_from(action_slice)?;
            actions.push(action);
            cursor.seek(SeekFrom::Current(action_len as i64)).unwrap();
            bytes_remaining -= action_len;
        }

        Ok(Bucket {
            len: len,
            weight: weight,
            watch_port: watch_port,
            watch_group: watch_group,
            actions: actions,
        })
    }
}

impl Into<Vec<u8>> for Bucket {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.len).unwrap();
        res.write_u16::<BigEndian>(self.len).unwrap();
        res.write_u32::<BigEndian>(self.watch_port.into()).unwrap();
        res.write_u32::<BigEndian>(self.watch_group).unwrap();
        for action in self.actions {
            res.extend_from_slice(&Into::<Vec<u8>>::into(action)[..]);
        }
        res
    }
}
