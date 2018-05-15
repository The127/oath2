use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::convert::{Into, TryFrom};
use std::io::{Cursor, Seek, SeekFrom};

use super::super::err::*;

#[derive(Debug, PartialEq, Clone)]
pub struct TableMod {
    table_id: u8,
    // pad 3 bytes
    /// reserved for future use
    config: u32,
}

unsafe impl Send for TableMod {}

impl<'a> TryFrom<&'a [u8]> for TableMod {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let table_id = cursor.read_u8().unwrap();
        cursor.seek(SeekFrom::Current(3)).unwrap(); // pad 3 bytes
        let config = cursor.read_u32::<BigEndian>().unwrap();
        Ok(TableMod {
            table_id: table_id,
            config: config,
        })
    }
}

impl Into<Vec<u8>> for TableMod {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u8(self.table_id).unwrap();
        res.write_u8(0).unwrap(); //pad 1 bytes
        res.write_u16::<BigEndian>(0).unwrap(); //pad 2 bytes
        res.write_u32::<BigEndian>(self.config).unwrap();
        res
    }
}
