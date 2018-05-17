use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::{Into, TryFrom};
use std::io::Cursor;

use super::super::err::*;
use super::ports::Port;

#[derive(Debug, PartialEq, Clone)]
pub struct PortStatus {
    reason: PortReason,
    //pad 7 bytes
    desc: Port,
}

impl<'a> TryFrom<&'a [u8]> for PortStatus {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let reason_raw = cursor.read_u8().unwrap();
        let reason = PortReason::from_u8(reason_raw).ok_or::<Error>(
            ErrorKind::UnknownValue(reason_raw as u64, stringify!(PortReason)).into(),
        )?;
        let desc = Port::try_from(&bytes[8..])?;

        Ok(PortStatus {
            reason: reason,
            desc: desc,
        })
    }
}

impl Into<Vec<u8>> for PortStatus {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u8(self.reason.to_u8().unwrap()).unwrap();

        //pad 7 bytes
        res.write_u8(0).unwrap();
        res.write_u16::<BigEndian>(0).unwrap();
        res.write_u32::<BigEndian>(0).unwrap();

        res.extend_from_slice(&Into::<Vec<u8>>::into(self.desc)[..]);

        res
    }
}

/// What changed about the physical port
#[derive(Primitive, PartialEq, Debug, Clone)]
pub enum PortReason {
    /// The port was added.
    Add = 0,
    /// The port was removed.
    Delete = 1,
    /// Some attribute of the port has changed.
    Modifiy = 2,
}
