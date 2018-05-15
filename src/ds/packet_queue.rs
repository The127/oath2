use super::super::err::*;
use super::ports::PortNumber;
use std::io::{SeekFrom, Seek, Cursor};
use std::path;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::{TryFrom, Into};

/// Length in bytes of a PacketQueue struct is 16 bytes.
pub const PACKET_QUEUE_LENGTH: usize = 16;

/// OpenFlow full description for a queue.
#[derive(Debug, PartialEq, Clone)]
pub struct PacketQueue {
    /// id for the specific queue.
    queue_id: u32,
    /// Port this queue is attached to.
    port: PortNumber,
    len: u16,
    // pad 6 bytes
    properties: Vec<QueuePropMessage>,
}

impl PacketQueue {
    pub fn read_len(cursor: &mut Cursor<&[u8]>) -> Result<usize> {
        // go to len position in the raw bytes
        cursor.seek(SeekFrom::Current(8)).unwrap();
        // read value and handle errors
        let len = match cursor.read_u16::<BigEndian>(){
            Ok(len) => len,
            Err(err) => {
                error!("Could not read packet queue len.{}{:?}{}{}", path::MAIN_SEPARATOR, cursor, path::MAIN_SEPARATOR, err);
                bail!(ErrorKind::CouldNotReadLength(
                    8,
                    stringify!(PacketQueue),
                ))
            }
        };
        // go back to start
        cursor.seek(SeekFrom::Current(-10)).unwrap();
        Ok(len as usize)
    }
}

impl<'a> TryFrom<&'a [u8]> for PacketQueue {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut properties = Vec::new();
        let mut cursor = Cursor::new(bytes);
        // first get "header" data and verify bytes.len()
        let queue_id = cursor.read_u32::<BigEndian>().chain_err(|| {
            let err_msg = format!("Could not read PacketQueue queue_id!{}Cursor: {:?}", path::MAIN_SEPARATOR, cursor);
            error!("{}", err_msg);
            err_msg
        })?;
        
        // read raw val
        let port = cursor.read_u32::<BigEndian>().chain_err(|| {
            let err_msg = format!("Could not read PacketQueue port!{}Cursor: {:?}", path::MAIN_SEPARATOR, cursor);
            error!("{}", err_msg);
            err_msg
        })?;
        // try to decode it
        // can a packetqueue port be a reserved keyword?
        let port = PortNumber::try_from(port)?;

        let len = cursor.read_u16::<BigEndian>().chain_err(|| {
            let err_msg = format!("Could not read PacketQueue len!{}Cursor: {:?}", path::MAIN_SEPARATOR, cursor);
            error!("{}", err_msg);
            err_msg
        })?;

        //put cursor to correct position
        cursor.seek(SeekFrom::Start(PACKET_QUEUE_LENGTH as u64)).unwrap();
        
        // check if bytes have correct length (now we know how long it should be)
        if bytes.len() != len as usize {
            bail!(ErrorKind::InvalidSliceLength(
                len as usize,
                bytes.len(),
                stringify!(PacketQueue),
            ));
        }

        //read properties
        while cursor.position() < bytes.len() as u64 {
            //read header first
            let queue_prop_header = 
                QueuePropHeader::try_from(&bytes[cursor.position() as usize..cursor.position() as usize+QUEUE_PROP_HEADER_LENGTH])?;
            
            //put cursor to correct position
            cursor.seek(SeekFrom::Current(QUEUE_PROP_HEADER_LENGTH as i64)).unwrap();

            //then read payload
            let prop_slice = &bytes[cursor.position() as usize..cursor.position() as usize + queue_prop_header.len as usize];
            let queue_prop_payload = match queue_prop_header.property {
                QueueProperties::MinRate => QueuePropPayload::Min(QueuePropMinRate::try_from(prop_slice)?),
                QueueProperties::MaxRate => QueuePropPayload::Max(QueuePropMaxRate::try_from(prop_slice)?),
                QueueProperties::Experimenter => QueuePropPayload::Experimenter(QueuePropExperimenter::try_from(prop_slice)?),
            };

            //put cursor to correct position
            cursor.seek(SeekFrom::Current(queue_prop_header.len as i64)).unwrap();

            //construct message
            let property = QueuePropMessage{
                header: queue_prop_header,
                payload: queue_prop_payload,
            };

            //add to vec
            properties.push(property);
        }

        Ok(PacketQueue{
            queue_id: queue_id,
            port: port,
            len: len,
            properties: properties,
        })
    }
}

impl Into<Vec<u8>> for PacketQueue {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(self.queue_id).unwrap();
        res.write_u32::<BigEndian>(self.port.into()).unwrap();
        res.write_u16::<BigEndian>(self.len).unwrap(); 
        res.write_u16::<BigEndian>(0).unwrap(); //pad 2 bytes
        res.write_u32::<BigEndian>(0).unwrap(); //pad 4 bytes
        for prop in self.properties {
            res.extend_from_slice(&Into::<Vec<u8>>::into(prop)[..]);
        }
        res
    }
}

#[derive(Primitive, PartialEq, Debug, Clone)]
pub enum QueueProperties {
    /// Minimum datarate guaranteed. 
    MinRate = 1, 
    /// Maximum datarate. 
    MaxRate = 2, 
    /// Experimenter defined property. 
    Experimenter = 0xffff,
}

/// QueuePropHeader length is always 8 bytes.
pub const QUEUE_PROP_HEADER_LENGTH: usize = 8;

/// Common description for a queue.
#[derive(Debug, PartialEq, Clone)]
pub struct QueuePropHeader {
    property: QueueProperties,
    len: u16,
    //pad 4 bytes
}

impl<'a> TryFrom<&'a [u8]> for QueuePropHeader {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let property_raw = cursor.read_u16::<BigEndian>().chain_err(|| {
            let err_msg = format!("Could not read QueuePropHeader property_raw!{}Cursor: {:?}", path::MAIN_SEPARATOR, cursor);
            error!("{}", err_msg);
            err_msg
        })?;
        let property = QueueProperties::from_u16(property_raw)
            .ok_or::<Error>(ErrorKind::UnknownValue(property_raw as u64, stringify!(QueueProperties)).into())?;

        Ok(QueuePropHeader{
            property: property,
            len: cursor.read_u16::<BigEndian>().chain_err(|| {
                let err_msg = format!("Could not read QueuePropHeader len!{}Cursor: {:?}", path::MAIN_SEPARATOR, cursor);
                error!("{}", err_msg);
                err_msg
            })?,
        })
        //padding 4 bytes by ignoring them
    }
}

impl Into<Vec<u8>> for QueuePropHeader {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.property.to_u16().unwrap()).unwrap();
        res.write_u16::<BigEndian>(self.len).unwrap();
        res.write_u32::<BigEndian>(0).unwrap(); //pad 4 bytes
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct QueuePropMessage {
    header: QueuePropHeader,
    payload: QueuePropPayload,
}

impl Into<Vec<u8>> for QueuePropMessage {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.extend_from_slice(&Into::<Vec<u8>>::into(self.header));
        res.extend_from_slice(&Into::<Vec<u8>>::into(self.payload));
        res
    }
}

/// enum holding all possible queue prop payloads
#[derive(Debug, PartialEq, Clone)]
pub enum QueuePropPayload {
    Min(QueuePropMinRate),
    Max(QueuePropMaxRate),
    Experimenter(QueuePropExperimenter),
}

impl Into<Vec<u8>> for QueuePropPayload {
    fn into(self) -> Vec<u8> {
        match self {
            QueuePropPayload::Min(min) => min.into(),
            QueuePropPayload::Max(max) => max.into(),
            QueuePropPayload::Experimenter(experimenter) => experimenter.into(),
        }
    }
}

/// Min-Rate queue property description.
#[derive(Debug, PartialEq, Clone)]
pub struct QueuePropMinRate {
    /// In 1/10 of a percent; >1000 -> disabled.
    rate: u16,
    //pad 6 bytes
}

impl<'a> TryFrom<&'a [u8]> for QueuePropMinRate {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(QueuePropMinRate{
            rate: cursor.read_u16::<BigEndian>().chain_err(|| {
                let err_msg = format!("Could not read QueuePropMinRate rate!{}Cursor: {:?}", path::MAIN_SEPARATOR, cursor);
                error!("{}", err_msg);
                err_msg
            })?,
        })
        //pad 6 bytes by ignoring them
    }
}

impl Into<Vec<u8>> for QueuePropMinRate {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.rate).unwrap();
        res.write_u16::<BigEndian>(0).unwrap(); //pad 2 bytes
        res.write_u32::<BigEndian>(0).unwrap(); //pad 4 bytes
        res
    }
}

/// Max-Rate queue property description.
#[derive(Debug, PartialEq, Clone)]
pub struct QueuePropMaxRate {
    /// In 1/10 of a percent; >1000 -> disabled.
    rate: u16,
    //pad 6 bytes
}

impl<'a> TryFrom<&'a [u8]> for QueuePropMaxRate {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(QueuePropMaxRate{
            rate: cursor.read_u16::<BigEndian>().chain_err(|| {
                let err_msg = format!("Could not read QueuePropMaxRate rate!{}Cursor: {:?}", path::MAIN_SEPARATOR, cursor);
                error!("{}", err_msg);
                err_msg
            })?,
        })
        //pad 6 bytes by ignoring them
    }
}

impl Into<Vec<u8>> for QueuePropMaxRate {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.rate).unwrap();
        res.write_u16::<BigEndian>(0).unwrap(); //pad 2 bytes
        res.write_u32::<BigEndian>(0).unwrap(); //pad 4 bytes
        res
    }
}

/// Experimenter queue property description.
#[derive(Debug, PartialEq, Clone)]
pub struct QueuePropExperimenter {
    experimenter: u32,
    //pad 4 bytes
    data: Vec<u8>,
}

impl<'a> TryFrom<&'a [u8]> for QueuePropExperimenter {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let experimenter = cursor.read_u32::<BigEndian>().chain_err(|| {
            let err_msg = format!("Could not read QueuePropExperimenter experimenter!{}Cursor: {:?}", path::MAIN_SEPARATOR, cursor);
            error!("{}", err_msg);
            err_msg
        })?;
        //pad 4 bytes by ignoring them
        let data = Vec::from(&bytes[8..]);
        Ok(QueuePropExperimenter{
            experimenter: experimenter,
            data: data,
        })
    }
}

impl Into<Vec<u8>> for QueuePropExperimenter {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(self.experimenter).unwrap();
        res.write_u32::<BigEndian>(0).unwrap(); //pad 4 bytes
        res.extend_from_slice(&self.data[..]);
        res
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    use super::super::ports::PortNumber;

    #[test]
    fn into_length(){
        let testee = PacketQueue {
            queue_id: 1,
            port: PortNumber::NormalPort(2),
            len: PACKET_QUEUE_LENGTH as u16,
            properties: Vec::new(),
        };
        let vec: Vec<u8> = testee.into();
        assert_eq!(PACKET_QUEUE_LENGTH, vec.len());
    }

    #[test]
    fn into_tryfrom() {
        let testee = PacketQueue {
            queue_id: 1,
            port: PortNumber::NormalPort(2),
            len: PACKET_QUEUE_LENGTH as u16,
            properties: Vec::new(),
        };
        let bytes = Into::<Vec<u8>>::into(testee.clone());
        let from = PacketQueue::try_from(&bytes[..]).expect("Error while decoding Port from bytes.");
        assert_eq!(testee, from);
    }

    #[test]
    fn into_length_qpe(){
        let testee = QueuePropExperimenter {
            experimenter: 0,
            //pad 4 bytes
            data: Vec::new(),
        };
        let vec: Vec<u8> = testee.into();
        assert_eq!(8, vec.len());
    }

    #[test]
    fn into_tryfrom_qpe() {
        let testee = QueuePropExperimenter {
            experimenter: 0,
            //pad 4 bytes
            data: Vec::new(),
        };
        let bytes = Into::<Vec<u8>>::into(testee.clone());
        let from = QueuePropExperimenter::try_from(&bytes[..]).expect("Error while decoding Port from bytes.");
        assert_eq!(testee, from);
    }

    #[test]
    fn into_length_qpmin(){
        let testee = QueuePropMinRate {
            rate: 0,
            //pad 6 bytes
        };
        let vec: Vec<u8> = testee.into();
        assert_eq!(8, vec.len());
    }

    #[test]
    fn into_tryfrom_qpmin() {
        let testee = QueuePropMinRate {
            rate: 0,
            //pad 6 bytes
        };
        let bytes = Into::<Vec<u8>>::into(testee.clone());
        let from = QueuePropMinRate::try_from(&bytes[..]).expect("Error while decoding Port from bytes.");
        assert_eq!(testee, from);
    }

    #[test]
    fn into_length_qpmax(){
        let testee = QueuePropMaxRate {
            rate: 0,
            //pad 6 bytes
        };
        let vec: Vec<u8> = testee.into();
        assert_eq!(8, vec.len());
    }

    #[test]
    fn into_tryfrom_qpmax() {
        let testee = QueuePropMaxRate {
            rate: 0,
            //pad 6 bytes
        };
        let bytes = Into::<Vec<u8>>::into(testee.clone());
        let from = QueuePropMaxRate::try_from(&bytes[..]).expect("Error while decoding Port from bytes.");
        assert_eq!(testee, from);
    }

    #[test]
    fn into_length_qph(){
        let testee = QueuePropHeader {
            property: QueueProperties::MinRate,
            len: QUEUE_PROP_HEADER_LENGTH as u16,
            //pad 4 bytes
        };
        let vec: Vec<u8> = testee.into();
        assert_eq!(QUEUE_PROP_HEADER_LENGTH, vec.len());
    }

    #[test]
    fn into_tryfrom_qph() {
        let testee = QueuePropHeader {
            property: QueueProperties::MinRate,
            len: QUEUE_PROP_HEADER_LENGTH as u16,
            //pad 4 bytes
        };
        let bytes = Into::<Vec<u8>>::into(testee.clone());
        let from = QueuePropHeader::try_from(&bytes[..]).expect("Error while decoding Port from bytes.");
        assert_eq!(testee, from);
    }
}
