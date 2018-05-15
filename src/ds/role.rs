use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::{TryFrom, Into};
use std::io::{Cursor, Seek, SeekFrom};

use super::super::err::*;

#[derive(Debug)]
pub struct Role {
    pub role: ControllerRole,
    // pad 4 bytes
    pub generation_id: u64,
}

unsafe impl Send for Role {}

impl Into<Vec<u8>> for Role{
    fn into(self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.write_u32::<BigEndian>(self.role.to_u32().unwrap()).unwrap();
        vec.write_u32::<BigEndian>(0).unwrap();
        vec.write_u64::<BigEndian>(self.generation_id).unwrap();
        vec
    }
}

impl<'a> TryFrom<&'a [u8]> for Role {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let role_raw = cursor.read_u32::<BigEndian>().unwrap();
        let role = ControllerRole::from_u32(role_raw)
            .ok_or::<Error>(ErrorKind::UnknownValue(role_raw as u64, stringify!(ControllerRole)).into())?;
        cursor.seek(SeekFrom::Current(4)).unwrap();//pad 4 bytes
        let generation_id = cursor.read_u64::<BigEndian>().unwrap();
        Ok(Role{
            role: role,
            generation_id: generation_id,
        })
    }
}

/// Controller roles. 
#[derive(Primitive, PartialEq, Debug, Clone)]
pub enum ControllerRole {
    /// Don't change current role. 
    NoChange = 0, 
    /// Default role, full access. 
    Equal = 1, 
    /// Full access, at most one master. 
    Master = 2,
    /// Read-only access.  
    Slave = 3, 
}

unsafe impl Send for ControllerRole {}
