use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::convert::{Into, TryFrom};
use std::io::{Cursor, Seek, SeekFrom};

use super::super::err::*;

#[derive(Debug, PartialEq, Clone)]
pub struct SwitchFeatures {
    pub datapath_id: u64,
    pub n_buffers: u32,
    pub n_tables: u8,
    pub auxiliary_id: u8,
    //pad 2 bytes
    pub capabilities: Capabilities,
    pub reserved: u32,
}

impl<'a> TryFrom<&'a [u8]> for SwitchFeatures {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);

        let datapath_id = cursor.read_u64::<BigEndian>().unwrap();
        let n_buffers = cursor.read_u32::<BigEndian>().unwrap();
        let n_tables = cursor.read_u8().unwrap();
        let auxiliary_id = cursor.read_u8().unwrap();
        cursor.seek(SeekFrom::Current(2)).unwrap(); // pad 2 bytes
        let capabilities =
            Capabilities::from_bits(cursor.read_u32::<BigEndian>().unwrap()).unwrap();
        let reserved = cursor.read_u32::<BigEndian>().unwrap();

        Ok(SwitchFeatures {
            datapath_id: datapath_id,
            n_buffers: n_buffers,
            n_tables: n_tables,
            auxiliary_id: auxiliary_id,
            capabilities: capabilities,
            reserved: reserved,
        })
    }
}

impl Into<Vec<u8>> for SwitchFeatures {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u64::<BigEndian>(self.datapath_id).unwrap();

        res.write_u32::<BigEndian>(self.n_buffers).unwrap();
        res.write_u8(self.n_tables).unwrap();
        res.write_u8(self.auxiliary_id).unwrap();
        res.write_u16::<BigEndian>(0).unwrap(); //pad 2 bytes

        res.write_u32::<BigEndian>(self.capabilities.bits())
            .unwrap();
        res.write_u32::<BigEndian>(self.reserved).unwrap();
        res
    }
}

bitflags!{
    /* Capabilities supported by the datapath. */
    pub struct Capabilities: u32 {
        /// Flow statistics.
        const FLOW_STATS = 1 << 0;
        /// Table statistics.
        const TABLE_STATS = 1 << 1;
        /// Port statistics.
        const PORT_STATS = 1 << 2;
        /// Group statistics.
        const GROUP_STATS = 1 << 3;
        /// Can reassemble IP fragments.
        const IP_REASM = 1 << 5;
        /// Queue statistics.
        const QUEUE_STATS = 1 << 6;
        /// Switch will block looping ports.
        const PORT_BLOCKED = 1 << 8;
    }
}
