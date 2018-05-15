use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::convert::{TryFrom, Into};
use std::io::{Cursor, Seek, SeekFrom};

use super::ports::{PortNumber, PortFeatures, PortConfig};
use super::hw_addr::{EthernetAddress, from_slice_eth};

use super::super::err::*;

#[derive(Debug, PartialEq, Clone)]
pub struct PortMod {
    port_no: PortNumber,
    // pad 4 bytes
    hw_addr: EthernetAddress,
    //pad 2 bytes,
    config: PortConfig,
    mask: PortConfig,
    advertise: PortFeatures,
    //pad 4 bytes
}

unsafe impl Send for PortMod {}

impl<'a> TryFrom<&'a [u8]> for PortMod{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let port_no = PortNumber::try_from(cursor.read_u32::<BigEndian>().unwrap())?;
        let hw_addr = &bytes[8..14];
        cursor.seek(SeekFrom::Start(16)).unwrap();

        // read raw version val
        let config = cursor.read_u32::<BigEndian>().unwrap();
        // try to decode it
        let config = PortConfig::from_bits(config)
            .ok_or::<Error>(ErrorKind::UnknownValue(config as u64, stringify!(PortConfig)).into())?;
        // read raw version val
        let mask = cursor.read_u32::<BigEndian>().unwrap();
        // try to decode it
        let mask = PortConfig::from_bits(mask)
            .ok_or::<Error>(ErrorKind::UnknownValue(mask as u64, stringify!(PortConfig)).into())?;

        // read raw version val
        let advertise = cursor.read_u32::<BigEndian>().unwrap();
        // try to decode it
        let advertise = PortFeatures::from_bits(advertise)
            .ok_or::<Error>(ErrorKind::UnknownValue(advertise as u64, stringify!(PortFeatures)).into())?;

        Ok(PortMod{
            port_no: port_no,
            hw_addr: from_slice_eth(hw_addr)?,
            config: config,
            mask: mask,
            advertise: advertise,
        })
    }
}

impl Into<Vec<u8>> for PortMod{
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(self.port_no.into()).unwrap(); 
        res.write_u32::<BigEndian>(0).unwrap(); // pad 4 bytes
        res.extend_from_slice(&self.hw_addr[..]);
        res.write_u16::<BigEndian>(0).unwrap(); // pad 2 bytes
        res.write_u32::<BigEndian>(self.config.bits()).unwrap();
        res.write_u32::<BigEndian>(self.mask.bits()).unwrap();
        res.write_u32::<BigEndian>(self.advertise.bits()).unwrap();
        res.write_u32::<BigEndian>(0).unwrap(); // pad 4 bytes
        res
    }
}
