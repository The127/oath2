use super::super::err::*;
use super::ports::PortNumber;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::{Into, TryFrom};
use std::io::{Cursor, Seek, SeekFrom};
use std::path;
use super::hw_addr;

/// Length of Math is 8 bytes.
pub const MATCH_LENGTH: usize = 8;

/// Fields to match against flows
#[derive(Debug, PartialEq, Clone)]
pub struct Match {
    ttype: MatchType,
    length: u16, //excluding last padding bytes
    //pad 4 bytes
    matches: Vec<TlvMatch>,
    /* Followed by:
     * - Exactly (length - 4) (possibly 0) bytes containing OXM TLVs, then
     * - Exactly ((length + 7)/8*8 - length) (between 0 and 7) bytes of
     * all-zero bytes
     * In summary, ofp_match is padded as needed, to make its overall size
     * a multiple of 8, to preserve alignement in structures using it.
     */
}

impl Match {
    pub fn read_len(cursor: &mut Cursor<&[u8]>) -> Result<usize> {
        // go to len position in the raw bytes
        cursor.seek(SeekFrom::Current(2)).unwrap();
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
                bail!(ErrorKind::CouldNotReadLength(2, stringify!(Match),))
            }
        };
        // go back to start
        cursor.seek(SeekFrom::Current(-4)).unwrap();
        Ok((len + ((len + 7)/8*8 - len)) as usize) // see above for this formula
    }
}

impl<'a> TryFrom<&'a [u8]> for Match {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let mut matches = Vec::new();

        // read raw version val
        let ttype_raw = cursor.read_u16::<BigEndian>().unwrap();
        // try to decode it
        let ttype = MatchType::from_u16(ttype_raw)
            .ok_or::<Error>(ErrorKind::UnknownValue(ttype_raw as u64, stringify!(MatchType)).into())?; 
        if ttype != MatchType::Standard {
            bail!(ErrorKind::UnsupportedValue(ttype_raw as u64, stringify!(MatchType)));
        }

        let length = cursor.read_u16::<BigEndian>().unwrap();

        let mut bytes_remaining = length as usize - MATCH_LENGTH;
        while bytes_remaining > 0 {

            let tlv_header_raw = cursor.read_u32::<BigEndian>().unwrap();
            let tlv_header = OxmTlvHeader(tlv_header_raw);
            let tlv_slice = &bytes[cursor.position() as usize..cursor.position() as usize + tlv_header.get_length() as usize];

            let tlv_match = TlvMatch::try_from(tlv_header, &tlv_slice[..])?;
            // ad to vector

            // count down by bytes read
            cursor.seek(SeekFrom::Current(tlv_match.tlv_header.get_length() as i64)).unwrap();
            bytes_remaining -= tlv_match.tlv_header.get_length() as usize;
            matches.push(tlv_match);
        }

        Ok(Match{
            ttype: ttype,
            length: length, 
            matches: matches,
        })
    }
}

impl Into<Vec<u8>> for Match{
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.ttype.to_u16().unwrap()).unwrap();
        res.write_u16::<BigEndian>(self.length).unwrap();
        for mmatch in self.matches {
            res.extend_from_slice(&Into::<Vec<u8>>::into(mmatch)[..]);
        }
        let pad_bytes_count = (self.length + 7)/8*8 - self.length;
        for _ in 0..pad_bytes_count {
            res.write_u8(0).unwrap();
        }
        res
    }
}
/// The match type indicates the match structure (set of fields that compose the
/// match) in use. The match type is placed in the type field at the beginning
/// of all match structures. The "OpenFlow Extensible Match" type corresponds
/// to OXM TLV format described below and must be supported by all OpenFlow
/// switches. Extensions that define other match types may be published on the
/// ONF wiki. Support for extensions is optional.
#[derive(Primitive, PartialEq, Debug, Clone)]
enum MatchType {
    /// Deprecated.
    Standard = 0, 
    /// OpenFlow Extensible Match 
    OXM = 1, 
}

#[derive(Debug, PartialEq, Clone)]
pub struct TlvMatch {
    pub tlv_header: OxmTlvHeader,
    payload: MatchPayload,
}

impl TlvMatch {
    pub fn try_from(tlv_header: OxmTlvHeader, match_slice: &[u8]) -> Result<TlvMatch> {
        // only support open flow basic oxm class

        //check if class is supported
        match OxmClass::from_u32(tlv_header.get_oxm_class()) {
            Some(cls) => (),
            None => bail!(ErrorKind::UnknownValue(tlv_header.get_oxm_class() as u64, stringify!(OxmClass))),
        }

        // read match
        let match_fields = OfbMatchFields::from_u32(tlv_header.get_oxm_field())
            .ok_or::<Error>(ErrorKind::UnknownValue(tlv_header.get_oxm_field() as u64, stringify!(OfbMatchFields)).into())?;
        let payload = match match_fields {
            OfbMatchFields::InPort =>{
                MatchPayload::InPort(PayloadInPort::try_from(match_slice)?)
            },
            OfbMatchFields::InPhyPort =>{
                MatchPayload::InPhyPort(PayloadInPhyPort::try_from(match_slice)?)
            },
            OfbMatchFields::Metadata =>{
                MatchPayload::Metadata(PayloadMetadata::try_from(match_slice)?)
            },
            OfbMatchFields::EthDst =>{
                MatchPayload::EthDst(PayloadEthDst::try_from(match_slice)?)
            },
            OfbMatchFields::EthSrc =>{
                MatchPayload::EthSrc(PayloadEthSrc::try_from(match_slice)?)
            },
            OfbMatchFields::EthType =>{
                MatchPayload::EthType(PayloadEthType::try_from(match_slice)?)
            },
            OfbMatchFields::VlanVid =>{
                MatchPayload::VlanVId(PayloadVlanVId::try_from(match_slice)?)
            },
            OfbMatchFields::VlanPcp =>{ 
                MatchPayload::VlanPcp(PayloadVlanPcp::try_from(match_slice)?)
            },
            OfbMatchFields::IpDscp =>{
                MatchPayload::IpDscp(PayloadIpDscp::try_from(match_slice)?)
            },
            OfbMatchFields::IpEcn =>{
                MatchPayload::IpEcn(PayloadIpEcn::try_from(match_slice)?)
            },
            OfbMatchFields::IpProto =>{
                MatchPayload::IpProto(PayloadIpProto::try_from(match_slice)?)
            },
            OfbMatchFields::IPv4Src =>{
                MatchPayload::IPv4Src(PayloadIPv4Src::try_from(match_slice)?)
            },
            OfbMatchFields::IPv4Dst =>{
                MatchPayload::IPv4Dst(PayloadIPv4Dst::try_from(match_slice)?)
            },
            OfbMatchFields::TcpSrc =>{
                MatchPayload::TcpSrc(PayloadTcpSrc::try_from(match_slice)?)
            },
            OfbMatchFields::TcpDst =>{
                MatchPayload::TcpDst(PayloadTcpDst::try_from(match_slice)?)
            },
            OfbMatchFields::UdpSrc =>{
                MatchPayload::UdpSrc(PayloadUdpSrc::try_from(match_slice)?)
            },
            OfbMatchFields::UdpDst =>{
                MatchPayload::UdpDst(PayloadUdpDst::try_from(match_slice)?)
            },
            OfbMatchFields::SctpSrc =>{
                MatchPayload::SctpSrc(PayloadSctpSrc::try_from(match_slice)?)
            },
            OfbMatchFields::SctpDst =>{
                MatchPayload::SctpDst(PayloadSctpDst::try_from(match_slice)?)
            },
            OfbMatchFields::IcmpV4TYype =>{
                MatchPayload::IcmpV4TYype(PayloadIcmpV4Type::try_from(match_slice)?)
            },
            OfbMatchFields::IcmpV4Code =>{
                MatchPayload::IcmpV4Code(PayloadIcmpV4Code::try_from(match_slice)?)
            },
            OfbMatchFields::ArpOp =>{
                MatchPayload::ArpOp(PayloadArpOp::try_from(match_slice)?)
            },
            OfbMatchFields::ArpSpa =>{
                MatchPayload::ArpSpa(PayloadArpSpa::try_from(match_slice)?)
            },
            OfbMatchFields::ArpTpa =>{
                MatchPayload::ArpTpa(PayloadArpTpa::try_from(match_slice)?)
            },
            OfbMatchFields::ArpSha =>{
                MatchPayload::ArpSha(PayloadArpSha::try_from(match_slice)?)
            },
            OfbMatchFields::ArpTha =>{
                MatchPayload::ArpTha(PayloadArpTha::try_from(match_slice)?)
            },
            OfbMatchFields::IPv6Src =>{
                MatchPayload::IPv6Src(PayloadIPv6Src::try_from(match_slice)?)
            },
            OfbMatchFields::IPv6Dst =>{
                MatchPayload::IPv6Dst(PayloadIPv6Dst::try_from(match_slice)?)
            },
            OfbMatchFields::IPv6FLabel =>{
                MatchPayload::IPv6FLabel(PayloadIPv6FLabel::try_from(match_slice)?)
            },
            OfbMatchFields::IcmpV6Type =>{
                MatchPayload::IcmpV6Type(PayloadIcmpV6Type::try_from(match_slice)?)
            },
            OfbMatchFields::IcmpV6Code =>{
                MatchPayload::IcmpV6Code(PayloadIcmpV6Code::try_from(match_slice)?)
            },
            OfbMatchFields::IPv6NdTarget =>{
                MatchPayload::IPv6NdTarget(PayloadIPv6NdTarget::try_from(match_slice)?)
            },
            OfbMatchFields::IPv6NdSll =>{
                MatchPayload::IPv6NdSll(PayloadIPv6NdSll::try_from(match_slice)?)
            },
            OfbMatchFields::IPv6NdTll =>{
                MatchPayload::IPv6NdTll(PayloadIPv6NdTll::try_from(match_slice)?)
            },
            OfbMatchFields::MplsLabel =>{
                MatchPayload::MplsLabel(PayloadMplsLabel::try_from(match_slice)?)
            },
            OfbMatchFields::MplsTc =>{
                MatchPayload::MplsTc(PayloadMplsTc::try_from(match_slice)?)
            },
            OfbMatchFields::MplsBos =>{
                MatchPayload::MplsBos(PayloadMplsBos::try_from(match_slice)?)
            },
            OfbMatchFields::PbbISid =>{
                MatchPayload::PbbISid(PayloadPbbISid::try_from(match_slice)?)
            },
            OfbMatchFields::TunnelId =>{
                MatchPayload::TunnelId(PayloadTunnelId::try_from(match_slice)?)
            },
            OfbMatchFields::IPv6ExtHdr => {
                MatchPayload::IPv6ExtHdr(PayloadIPv6ExtHdr::try_from(match_slice)?)
            },
        };
        
        // create match
        let tlv_match = TlvMatch{
            tlv_header: tlv_header,
            payload: payload,
        };
        Ok(tlv_match)
    }
}

impl Into<Vec<u8>> for TlvMatch{
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(self.tlv_header.0).unwrap();
        res.extend_from_slice(&Into::<Vec<u8>>::into(self.payload));
        res
    }
}

bitfield!{
    pub struct OxmTlvHeader(u32);
    impl Debug;

    u32;
    pub get_length, set_length: 7, 0;
    pub get_hasmask, set_hasmask: 8, 8;
    pub get_oxm_field, set_oxm_field: 15, 9;
    pub get_oxm_class, set_oxm_class: 31, 16;
}

impl Clone for OxmTlvHeader{
    fn clone(&self) -> Self {
        OxmTlvHeader(self.0.clone())
    }
}

impl ::std::cmp::PartialEq for OxmTlvHeader{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

/// OXM Class IDs.
/// The high order bit differentiate reserved classes from member classes.
/// Classes 0x0000 to 0x7FFF are member classes, allocated by ONF.
/// Classes 0x8000 to 0xFFFE are reserved classes, reserved for standardisation.
#[derive(Primitive, PartialEq, Debug, Clone)]
enum OxmClass {
    /// Backward compatibility with NXM
    XmcNxm0 = 0x0000, 
    /// Backward compatibility with NXM
    XmcNxm1 = 0x0001, 
    /// Basic class for OpenFlow
    XmcOpenFlowBasic = 0x8000,
    /// Experimenter class
    XmcExperimenter = 0xFFFF, 
}

#[derive(Primitive, PartialEq, Debug, Clone)]
enum OfbMatchFields {
    /// Switch input port. 
    InPort = 0, 
    /// Switch physical input port. 
    InPhyPort = 1,
    /// Metadata passed between tables. 
    Metadata = 2,
    /// Ethernet destination address. 
    EthDst = 3,
    /// Ethernet source address. 
    EthSrc = 4,
    /// Ethernet frame type. 
    EthType = 5,
    /// VLAN id. 
    VlanVid = 6,
    /// VLAN priority. 
    VlanPcp = 7,
    /// IP DSCP (6 bits in ToS field). 
    IpDscp = 8,
    /// IP ECN (2 bits in ToS field). 
    IpEcn = 9, 
    /// IP protocol. 
    IpProto = 10, 
    /// IPv4 source address. 
    IPv4Src = 11, 
    /// IPv4 destination address. 
    IPv4Dst = 12, 
    /// TCP source port. 
    TcpSrc = 13, 
    /// TCP destination port. 
    TcpDst = 14, 
    /// UDP source port. 
    UdpSrc = 15, 
    /// UDP destination port. 
    UdpDst = 16, 
    /// SCTP source port. 
    SctpSrc = 17, 
    /// SCTP destination port. 
    SctpDst = 18, 
    /// ICMP type. 
    IcmpV4TYype = 19, 
    /// ICMP code. 
    IcmpV4Code = 20, 
    /// ARP opcode. 
    ArpOp = 21, 
    /// ARP source IPv4 address. 
    ArpSpa = 22, 
    /// ARP target IPv4 address. 
    ArpTpa = 23, 
    /// ARP source hardware address. 
    ArpSha = 24, 
    /// ARP target hardware address. 
    ArpTha = 25, 
    /// IPv6 source address. 
    IPv6Src = 26, 
    /// IPv6 destination address. 
    IPv6Dst = 27, 
    /// IPv6 Flow Label 
    IPv6FLabel = 28, 
    /// ICMPv6 type. 
    IcmpV6Type = 29, 
    /// ICMPv6 code. 
    IcmpV6Code = 30, 
    /// Target address for ND. 
    IPv6NdTarget = 31, 
    /// Source link-layer for ND. 
    IPv6NdSll = 32, 
    /// Target link-layer for ND. 
    IPv6NdTll = 33, 
    /// MPLS label. 
    MplsLabel = 34, 
    /// MPLS TC. 
    MplsTc = 35, 
    /// MPLS BoS bit. 
    MplsBos = 36, 
    /// PBB I-SID. 
    PbbISid = 37, 
    /// Logical Port Metadata. 
    TunnelId = 38, 
    /// IPv6 Extension Header pseudo-field
    IPv6ExtHdr = 39,
}

#[derive(Debug, PartialEq, Clone)]
pub enum MatchPayload {
    /// Switch input port. 
    InPort(PayloadInPort), 
    /// Switch physical input port. 
    InPhyPort(PayloadInPhyPort),
    /// Metadata passed between tables. 
    Metadata(PayloadMetadata),
    /// Ethernet destination address. 
    EthDst(PayloadEthDst),
    /// Ethernet source address. 
    EthSrc(PayloadEthSrc),
    /// Ethernet frame type. 
    EthType(PayloadEthType),
    /// VLAN id. 
    VlanVId(PayloadVlanVId),
    /// VLAN priority. 
    VlanPcp(PayloadVlanPcp),
    /// IP DSCP (6 bits in ToS field). 
    IpDscp(PayloadIpDscp),
    /// IP ECN (2 bits in ToS field). 
    IpEcn(PayloadIpEcn), 
    /// IP protocol. 
    IpProto(PayloadIpProto), 
    /// IPv4 source address. 
    IPv4Src(PayloadIPv4Src), 
    /// IPv4 destination address. 
    IPv4Dst(PayloadIPv4Dst), 
    /// TCP source port. 
    TcpSrc(PayloadTcpSrc), 
    /// TCP destination port. 
    TcpDst(PayloadTcpDst), 
    /// UDP source port. 
    UdpSrc(PayloadUdpSrc), 
    /// UDP destination port. 
    UdpDst(PayloadUdpDst), 
    /// SCTP source port. 
    SctpSrc(PayloadSctpSrc), 
    /// SCTP destination port. 
    SctpDst(PayloadSctpDst), 
    /// ICMP type. 
    IcmpV4TYype(PayloadIcmpV4Type), 
    /// ICMP code. 
    IcmpV4Code(PayloadIcmpV4Code), 
    /// ARP opcode. 
    ArpOp(PayloadArpOp), 
    /// ARP source IPv4 address. 
    ArpSpa(PayloadArpSpa), 
    /// ARP target IPv4 address. 
    ArpTpa(PayloadArpTpa), 
    /// ARP source hardware address. 
    ArpSha(PayloadArpSha), 
    /// ARP target hardware address. 
    ArpTha(PayloadArpTha), 
    /// IPv6 source address. 
    IPv6Src(PayloadIPv6Src), 
    /// IPv6 destination address. 
    IPv6Dst(PayloadIPv6Dst), 
    /// IPv6 Flow Label 
    IPv6FLabel(PayloadIPv6FLabel), 
    /// ICMPv6 type. 
    IcmpV6Type(PayloadIcmpV6Type), 
    /// ICMPv6 code. 
    IcmpV6Code(PayloadIcmpV6Code), 
    /// Target address for ND. 
    IPv6NdTarget(PayloadIPv6NdTarget), 
    /// Source link-layer for ND. 
    IPv6NdSll(PayloadIPv6NdSll), 
    /// Target link-layer for ND. 
    IPv6NdTll(PayloadIPv6NdTll), 
    /// MPLS label. 
    MplsLabel(PayloadMplsLabel), 
    /// MPLS TC. 
    MplsTc(PayloadMplsTc), 
    /// MPLS BoS bit. 
    MplsBos(PayloadMplsBos), 
    /// PBB I-SID. 
    PbbISid(PayloadPbbISid), 
    /// Logical Port Metadata. 
    TunnelId(PayloadTunnelId), 
    /// IPv6 Extension Header pseudo-field
    IPv6ExtHdr(PayloadIPv6ExtHdr),
}

impl Into<Vec<u8>> for MatchPayload{
    fn into(self) -> Vec<u8> {
        match self{
            MatchPayload::InPort(payload) => payload.into(),
            MatchPayload::InPhyPort(payload) => payload.into(),
            MatchPayload::Metadata(payload) => payload.into(),
            MatchPayload::EthDst(payload) => payload.into(),
            MatchPayload::EthSrc(payload) => payload.into(),
            MatchPayload::EthType(payload) => payload.into(),
            MatchPayload::VlanVId(payload) => payload.into(),
            MatchPayload::VlanPcp(payload) => payload.into(),
            MatchPayload::IpDscp(payload) => payload.into(),
            MatchPayload::IpEcn(payload) => payload.into(),
            MatchPayload::IpProto(payload) => payload.into(),
            MatchPayload::IPv4Src(payload) => payload.into(),
            MatchPayload::IPv4Dst(payload) => payload.into(),
            MatchPayload::TcpSrc(payload) => payload.into(),
            MatchPayload::TcpDst(payload) => payload.into(),
            MatchPayload::UdpSrc(payload) => payload.into(),
            MatchPayload::UdpDst(payload) => payload.into(),
            MatchPayload::SctpSrc(payload) => payload.into(),
            MatchPayload::SctpDst(payload) => payload.into(),
            MatchPayload::IcmpV4TYype(payload) => payload.into(),
            MatchPayload::IcmpV4Code(payload) => payload.into(),
            MatchPayload::ArpOp(payload) => payload.into(),
            MatchPayload::ArpSpa(payload) => payload.into(),
            MatchPayload::ArpTpa(payload) => payload.into(),
            MatchPayload::ArpSha(payload) => payload.into(),
            MatchPayload::ArpTha(payload) => payload.into(),
            MatchPayload::IPv6Src(payload) => payload.into(),
            MatchPayload::IPv6Dst(payload) => payload.into(),
            MatchPayload::IPv6FLabel(payload) => payload.into(),
            MatchPayload::IcmpV6Type(payload) => payload.into(),
            MatchPayload::IcmpV6Code(payload) => payload.into(),
            MatchPayload::IPv6NdTarget(payload) => payload.into(),
            MatchPayload::IPv6NdSll(payload) => payload.into(),
            MatchPayload::IPv6NdTll(payload) => payload.into(),
            MatchPayload::MplsLabel(payload) => payload.into(),
            MatchPayload::MplsTc(payload) => payload.into(),
            MatchPayload::MplsBos(payload) => payload.into(),
            MatchPayload::PbbISid(payload) => payload.into(),
            MatchPayload::TunnelId(payload) => payload.into(),
            MatchPayload::IPv6ExtHdr(payload) => payload.into(),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadInPort {
    ingress_port: PortNumber,
}

impl<'a> TryFrom<&'a [u8]> for PayloadInPort{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadInPort{
            ingress_port: PortNumber::try_from(cursor.read_u32::<BigEndian>().unwrap())?,
        })
    }
}

impl Into<Vec<u8>> for PayloadInPort {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(self.ingress_port.into()).unwrap();
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadInPhyPort {
    phy_port: u32,
}

impl<'a> TryFrom<&'a [u8]> for PayloadInPhyPort{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadInPhyPort{
            phy_port: cursor.read_u32::<BigEndian>().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadInPhyPort {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(self.phy_port).unwrap();
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadMetadata {
    metadata: u64,
}

impl<'a> TryFrom<&'a [u8]> for PayloadMetadata{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadMetadata{
            metadata: cursor.read_u64::<BigEndian>().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadMetadata {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u64::<BigEndian>(self.metadata).unwrap();
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadEthDst {
    eth_dst: hw_addr::EthernetAddress,
}

impl<'a> TryFrom<&'a [u8]> for PayloadEthDst{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(PayloadEthDst{
            eth_dst: hw_addr::from_slice_eth(bytes)?,
        })
    }
}

impl Into<Vec<u8>> for PayloadEthDst {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.extend_from_slice(&self.eth_dst[..]);
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadEthSrc {
    eth_src: hw_addr::EthernetAddress,
}

impl<'a> TryFrom<&'a [u8]> for PayloadEthSrc{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(PayloadEthSrc{
            eth_src: hw_addr::from_slice_eth(bytes)?,
        })
    }
}

impl Into<Vec<u8>> for PayloadEthSrc {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.extend_from_slice(&self.eth_src[..]);
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadEthType {
    ttype: EtherType,
}

impl<'a> TryFrom<&'a [u8]> for PayloadEthType{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let raw_ttype = cursor.read_u16::<BigEndian>().unwrap();
        Ok(PayloadEthType{
            ttype: EtherType::from_u16(raw_ttype)
                .ok_or::<Error>(ErrorKind::UnknownValue(raw_ttype as u64, stringify!(EtherType)).into())?,
        })
    }
}

impl Into<Vec<u8>> for PayloadEthType {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.ttype.to_u16().unwrap()).unwrap();
        res
    }
}

/// Ether type from https://en.wikipedia.org/wiki/EtherType
#[derive(Primitive, PartialEq, Debug, Clone)]
pub enum EtherType {
    IPv4 = 0x0800,
    Arp = 0x0806,
    WakeOnLan = 0x0842,
    IetfTrillProtocol = 0x22F3,
    StreamReservationProtocol = 0x22EA,
    DECnetPhaseIV = 0x6003,
    ReverseAddressResolutionProtocol = 0x8035,
    AppleTalk = 0x809B,
    AARP = 0x80F3,
    VlanTaggedFrameShortestPathBridging = 0x8100,
    IPX = 0x8137,
    QNXQnet = 0x8204,
    IPv6 = 0x86DD,
    EthernetFlowControl = 0x8808,
    EthernetSlowProtocols = 0x8809,
    CobraNet = 0x8819,
    MplsUnicast = 0x8847,
    MplsMulticast = 0x8848,
    PPPoEDiscoveryStage = 0x8863,
    PPPoESessionStage = 0x8864,
    IntelAdvancedNetworkingServices = 0x886D,
    JumboFrames = 0x8870,
    HomePlug10MME = 0x887B,
    EapOverLan = 0x888E,
    PROFINETProtocol = 0x8892,
    HyperSCSI = 0x889A,
    AtaOverEthernet = 0x88A2,
    EtherCAT = 0x88A4,
    ProviderBridgingSHortestPathBridging = 0x88A8,
    EthernetPowerlink = 0x88AB,
    GOOSE = 0x88B8,
    GSEManagementServices = 0x88B9,
    SV = 0x88BA,
    LLDP = 0x88CC,
    SERCOSIII = 0x88CD,
    WSMP = 0x88DC,
    HOMEPlugAvMMe = 0x88E1,
    MediaRedundancyProtocol = 0x88E3,
    MACSecurity = 0x88E5,
    ProviderBackboneBridges = 0x88E7,
    PrecisionTimeProtocol = 0x88F7,
    NcSi = 0x88F8,
    ParallelRedundancyProtocol = 0x88FB,
    CFM = 0x8902,
    FCoE = 0x8906,
    FCoEInitializationProtocol = 0x8914,
    RoCE = 0x8915,
    TTE = 0x891D,
    HST = 0x892F,
    EthernetConfigurationTestingProtocol = 0x9000,
    VlanTaggedWithDoubleTagging = 0x9100,
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadVlanVId {
    vlan_id: u16, // 12+1 bits
}

impl<'a> TryFrom<&'a [u8]> for PayloadVlanVId{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadVlanVId{
            vlan_id: cursor.read_u16::<BigEndian>().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadVlanVId {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.vlan_id).unwrap();
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadVlanPcp {
    vlan_pcp: u8, // 3 bits
}

impl<'a> TryFrom<&'a [u8]> for PayloadVlanPcp{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadVlanPcp{
            vlan_pcp: cursor.read_u8().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadVlanPcp {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u8(self.vlan_pcp).unwrap();
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadIpDscp {
    ip_dscp: u8, // 6 bits
}

impl<'a> TryFrom<&'a [u8]> for PayloadIpDscp{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadIpDscp{
            ip_dscp: cursor.read_u8().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadIpDscp {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u8(self.ip_dscp).unwrap();
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadIpEcn {
    ip_enc: u8, // 2 bits
}

impl<'a> TryFrom<&'a [u8]> for PayloadIpEcn{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadIpEcn{
            ip_enc: cursor.read_u8().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadIpEcn {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u8(self.ip_enc).unwrap();
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadIpProto {
    ip_proto: IpProto,
}

impl<'a> TryFrom<&'a [u8]> for PayloadIpProto{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let ip_proto_raw = cursor.read_u16::<BigEndian>().unwrap();
        Ok(PayloadIpProto{
            ip_proto: IpProto::from_u16(ip_proto_raw)
                .ok_or::<Error>(ErrorKind::UnknownValue(ip_proto_raw as u64, stringify!(IpProto)).into())?,
        })
    }
}

impl Into<Vec<u8>> for PayloadIpProto {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u8(self.ip_proto.to_u8().unwrap()).unwrap();
        res
    }
}

/// IP_PROTO ids from https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
#[derive(Primitive, PartialEq, Debug, Clone)]
pub enum IpProto {
    Hopopt = 0,
    Icmp = 1,
    Igmp = 2,
    Ggp = 3,
    IPv4 = 4,
    St = 5,
    Tcp = 6,
    Cbt = 7,
    Egp = 8,
    Igp = 9,
    BbnRccMon = 10,
    NvpII = 11,
    Pup = 12,
    /// deprecated
    Argus = 13,
    Emcon = 14,
    XNet = 15,
    Chaos = 16,
    Udp = 17,
    Mux = 18,
    DcnMeas = 19,
    Hmp = 20,
    Prm = 21,
    XnsIdp = 22,
    Trunk1 = 23,
    Trunk2 = 24,
    Leaf1 = 25,
    Leaf2 = 26,
    Rdp = 27,
    Irtp = 28,
    IsoTp4 = 29,
    Netblt = 30,
    MfeNsp = 31,
    MeritInp = 32,
    Dccp = 33,
    Pc3 = 34,
    Idpr = 35,
    Xtp = 36,
    Ddp = 37,
    IdpCmtp = 38,
    Tppp = 39,
    IL = 40,
    IPv6 = 41,
    Sdrp = 42,
    IPv6Route = 43,
    Ipv6Frag = 44,
    Idrp = 45,
    Rsvp = 46,
    Gre = 47,
    Dsr = 48,
    Bna = 49,
    Esp = 50,
    Ah = 51,
    INlsp = 52,
    /// deprecated
    Swipe = 53,
    Narp = 54,
    Mobile = 55,
    Tlsp = 56,
    Skip = 57,
    IPv6Icmp = 58,
    IPv6NoNxt = 59,
    IPv6Opts = 60,
    AnyHostInternal = 61,
    Cftp = 62,
    AnyLocalNetwork = 63,
    SatExpak = 64,
    Kryptolan = 65,
    Rvd = 66,
    Ippc = 67,
    AnyDistributedFileSystem = 68,
    SatMon = 69,
    Visa = 70,
    Ipcv = 71,
    Cpnx = 72,
    Cphb = 73,
    Wsn = 74,
    Pvp = 75,
    BrSatMon = 76,
    SunNd = 77,
    WbMon = 78,
    WbExpak = 79,
    IsoIp = 80,
    Vmtp = 81,
    SecureVmtp = 82,
    Vines = 83,
    TtpIptm = 84,
    NsfnetIgp = 85,
    Dgp = 86,
    Tcf = 87,
    Eigrp = 88,
    Ospfigp = 89,
    SpriteRPC = 90,
    Larp = 91,
    Mtp = 92,
    Ax25 = 93,
    Ipip = 94,
    /// deprecated
    Micp = 95,
    SccSp = 96,
    EtherIp = 97,
    EnCap = 98,
    AnyPrivateEncryptionScheme = 99,
    Gmtp = 100,
    Ifmp = 101,
    Pnni = 102,
    Pim = 103,
    Aris = 104,
    Scps = 105,
    Qnx = 106,
    AN = 107,
    IPComp = 108,
    Snp = 109,
    CompaqPeer = 110,
    IpxInIp = 111,
    Vrrp = 112,
    Pgm = 113,
    Any0HopProtocol = 114,
    L2Tp = 115,
    Ddx = 116,
    Iatp = 117,
    Stp = 118,
    Srp = 119,
    Uti = 120,
    Smp = 121,
    /// deprecated
    Sm = 122,
    Ptp = 123,
    IsisOverIPv4 = 124,
    Fire = 125,
    Crtp = 126,
    Crudp = 127,
    Sscopmce = 128,
    Iplt = 129,
    Sps = 130,
    Pipe = 131,
    Sctp = 132,
    Fc = 133,
    RsvpE2eIgnore = 134,
    MobilityHeader = 135,
    UdpLite = 136,
    MplsInIp = 137,
    Manet = 138,
    Hip = 139,
    Shim6 = 140,
    Wesp = 141,
    Rohc = 142,
    Testing1 = 253,
    Testing2 = 254,
    Reserved = 255,
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadIPv4Src {
    ipv4_src: hw_addr::IPv4Address,
}

impl<'a> TryFrom<&'a [u8]> for PayloadIPv4Src{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(PayloadIPv4Src{
            ipv4_src: hw_addr::from_slice_v4(bytes)?,
        })
    }
}

impl Into<Vec<u8>> for PayloadIPv4Src {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.extend_from_slice(&self.ipv4_src[..]);
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadIPv4Dst {
    ipv4_dst: hw_addr::IPv4Address,
}

impl<'a> TryFrom<&'a [u8]> for PayloadIPv4Dst{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(PayloadIPv4Dst{
            ipv4_dst: hw_addr::from_slice_v4(bytes)?,
        })
    }
}

impl Into<Vec<u8>> for PayloadIPv4Dst {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.extend_from_slice(&self.ipv4_dst[..]);
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadTcpSrc {
    src_port: u16,
}

impl<'a> TryFrom<&'a [u8]> for PayloadTcpSrc{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadTcpSrc{
            src_port: cursor.read_u16::<BigEndian>().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadTcpSrc {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.src_port).unwrap();
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadTcpDst {
    dst_port: u16,
}

impl<'a> TryFrom<&'a [u8]> for PayloadTcpDst{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadTcpDst{
            dst_port: cursor.read_u16::<BigEndian>().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadTcpDst {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.dst_port).unwrap();
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadUdpSrc {
    src_port: u16,
}

impl<'a> TryFrom<&'a [u8]> for PayloadUdpSrc{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadUdpSrc{
            src_port: cursor.read_u16::<BigEndian>().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadUdpSrc {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.src_port).unwrap();
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadUdpDst {
    dst_port: u16,
}

impl<'a> TryFrom<&'a [u8]> for PayloadUdpDst{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadUdpDst{
            dst_port: cursor.read_u16::<BigEndian>().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadUdpDst {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.dst_port).unwrap();
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadSctpSrc {
    src_port: u16,
}

impl<'a> TryFrom<&'a [u8]> for PayloadSctpSrc{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadSctpSrc{
            src_port: cursor.read_u16::<BigEndian>().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadSctpSrc {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.src_port).unwrap();
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadSctpDst {
    dst_port: u16,
}

impl<'a> TryFrom<&'a [u8]> for PayloadSctpDst{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadSctpDst{
            dst_port: cursor.read_u16::<BigEndian>().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadSctpDst {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.dst_port).unwrap();
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadIcmpV4Type {
    ttype: IcmpType,
}

impl<'a> TryFrom<&'a [u8]> for PayloadIcmpV4Type{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let raw_ttype = cursor.read_u8().unwrap();
        Ok(PayloadIcmpV4Type{
            ttype: IcmpType::from_u8(raw_ttype)
                .ok_or::<Error>(ErrorKind::UnknownValue(raw_ttype as u64, stringify!(IcmpType)).into())?,
        })
    }
}

impl Into<Vec<u8>> for PayloadIcmpV4Type {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u8(self.ttype.to_u8().unwrap()).unwrap();
        res
    }
}

/// icmp types from https://de.wikipedia.org/wiki/Internet_Control_Message_Protocol
#[derive(Primitive, PartialEq, Debug, Clone)]
pub enum IcmpType {
    EchoReply = 0,
    DestinationUnreachable = 3,
    SourceQuench = 4,
    Redirect = 5,
    EchoRequest = 8,
    RouterAdvertisement = 9,
    RouterSolicitation = 10,
    TimeExceeded = 11,
    ParameterProblem = 12,
    Timestamp = 13,
    TimestampReply = 14,
    InformationRequest = 15,
    InformationReply = 16,
    AddressMaskRequest = 17,
    AddressMaskReply = 18,
    ReservedSecurity = 19,
    RobustExperiment20 = 20,
    RobustExperiment21 = 21,
    RobustExperiment22 = 22,
    RobustExperiment23 = 23,
    RobustExperiment24 = 24,
    RobustExperiment25 = 25,
    RobustExperiment26 = 26,
    RobustExperiment27 = 27,
    RobustExperiment28 = 28,
    RobustExperiment29 = 29,
    Traceroute = 30,
    DatagramConversionError = 31,
    MobileHostRedirect = 32,
    IPv6WhereAreYou = 33,
    IPv6IAmHere = 34,
    MobileRegistrationRequest = 35,
    MobileRegistrationReply = 36,
    DomainNameRequest = 37,
    DomainNameReply = 38,
    Dkip = 39,
    Photuris = 40,
    ExperimentalMobility41 = 41,
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadIcmpV4Code {
    code: u8,
}

impl<'a> TryFrom<&'a [u8]> for PayloadIcmpV4Code{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadIcmpV4Code{
            code: cursor.read_u8().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadIcmpV4Code {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u8(self.code).unwrap();
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadArpOp {
    arp_op: ArpOp,
}

impl<'a> TryFrom<&'a [u8]> for PayloadArpOp{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let raw_arp_op = cursor.read_u16::<BigEndian>().unwrap();
        Ok(PayloadArpOp{
            arp_op: ArpOp::from_u16(raw_arp_op)
                .ok_or::<Error>(ErrorKind::UnknownValue(raw_arp_op as u64, stringify!(ArpOp)).into())?,
        })
    }
}

impl Into<Vec<u8>> for PayloadArpOp {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.arp_op.to_u16().unwrap()).unwrap();
        res
    }
}

/// icmp types from https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
#[derive(Primitive, PartialEq, Debug, Clone)]
pub enum ArpOp {
    Reserved0 = 0,
    Request = 1,
    Reply = 2,
    RequestReverse = 3,
    ReplyReverse = 4,
    DrArpRequest = 5,
    DrArpReply = 6,
    DrArpError = 7,
    InArpRequest = 8,
    InArpReply = 9,
    ArpNak = 10,
    MarsRequest = 11,
    MarsMulti = 12,
    MarsMServ = 13,
    MarsJoin = 14,
    MarsLeave = 15,
    MarsNak = 16,
    MarsUnserv = 17,
    MarsSJoin = 18,
    MarsSLeave = 19,
    MarsGrouplistRequest = 20,
    MarsGrouListReply = 21,
    MarsRedirectMap = 22,
    MarsUnArp = 23,
    OpExp1 = 24,
    OpExp2 = 25,
    Reserved66535 = 66535,
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadArpSpa {
    arp_spa: hw_addr::IPv4Address,
}

impl<'a> TryFrom<&'a [u8]> for PayloadArpSpa{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(PayloadArpSpa{
            arp_spa: hw_addr::from_slice_v4(&bytes[..])?,
        })
    }
}

impl Into<Vec<u8>> for PayloadArpSpa {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.extend_from_slice(&self.arp_spa[..]);
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadArpTpa {
    arp_tpa: hw_addr::IPv4Address,
}

impl<'a> TryFrom<&'a [u8]> for PayloadArpTpa{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(PayloadArpTpa{
            arp_tpa: hw_addr::from_slice_v4(&bytes[..])?,
        })
    }
}

impl Into<Vec<u8>> for PayloadArpTpa {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.extend_from_slice(&self.arp_tpa[..]);
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadArpSha {
    arp_sha: hw_addr::EthernetAddress,
}

impl<'a> TryFrom<&'a [u8]> for PayloadArpSha{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(PayloadArpSha{
            arp_sha: hw_addr::from_slice_eth(&bytes[..])?,
        })
    }
}

impl Into<Vec<u8>> for PayloadArpSha {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.extend_from_slice(&self.arp_sha[..]);
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadArpTha {
    arp_tha: hw_addr::EthernetAddress,
}

impl<'a> TryFrom<&'a [u8]> for PayloadArpTha{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(PayloadArpTha{
            arp_tha: hw_addr::from_slice_eth(&bytes[..])?,
        })
    }
}

impl Into<Vec<u8>> for PayloadArpTha {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.extend_from_slice(&self.arp_tha[..]);
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadIPv6Src {
    ipv6_src: hw_addr::IPv6Address,
}

impl<'a> TryFrom<&'a [u8]> for PayloadIPv6Src{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(PayloadIPv6Src{
            ipv6_src: hw_addr::from_slice_v6(&bytes[..])?,
        })
    }
}

impl Into<Vec<u8>> for PayloadIPv6Src {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.extend_from_slice(&self.ipv6_src[..]);
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadIPv6Dst {
    ipv6_dst: hw_addr::IPv6Address,
}

impl<'a> TryFrom<&'a [u8]> for PayloadIPv6Dst{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(PayloadIPv6Dst{
            ipv6_dst: hw_addr::from_slice_v6(&bytes[..])?,
        })
    }
}

impl Into<Vec<u8>> for PayloadIPv6Dst {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.extend_from_slice(&self.ipv6_dst[..]);
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadIPv6FLabel {
    flabel: u32, // 20 bits
}

impl<'a> TryFrom<&'a [u8]> for PayloadIPv6FLabel{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadIPv6FLabel{
            flabel: cursor.read_u32::<BigEndian>().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadIPv6FLabel {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(self.flabel).unwrap();
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadIcmpV6Type {
    ttype: IcmpV6Type,
}

impl<'a> TryFrom<&'a [u8]> for PayloadIcmpV6Type{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let raw_ttype = cursor.read_u8().unwrap();
        Ok(PayloadIcmpV6Type{
            ttype: IcmpV6Type::from_u8(raw_ttype)
                .ok_or::<Error>(ErrorKind::UnknownValue(raw_ttype as u64, stringify!(IcmpV6Type)).into())?,
        })
    }
}

impl Into<Vec<u8>> for PayloadIcmpV6Type {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u8(self.ttype.to_u8().unwrap()).unwrap();
        res
    }
}

#[derive(Primitive, PartialEq, Debug, Clone)]
pub enum IcmpV6Type {
    Reserved0 = 0,
    DestinationUnreachable = 1,
    PacketTooBig = 2,
    TimeExceeded = 3,
    ParameterProblem = 4,
    PrivateExperimentation100 = 100,
    PrivateExperimentation101 = 101,
    Reserved127 = 127,
    EchoRequest = 128,
    EchoReply = 129,
    MulticastListenerQuery = 130,
    MulticastListenerReport = 131,
    MulticastListenerDone = 132,
    RouterSolicitation = 133,
    RouterAdvertisement = 134,
    NeighborSolicitation = 135,
    NeighborAdvertisement = 136,
    RedirectMessage = 137,
    RouterRenumbering = 138,
    IcmpNodeInformationQuery = 139,
    IcmpNodeInformationResponse = 140,
    InverseNeighborDiscoverySolicitationMessage = 141,
    InverseNeighborDiscoveryAdvertisementMessage = 142,
    Version2MulticastListenerReport = 143,
    HomeAgentAddressDiscoveryRequestMessage = 144,
    HomeAgentAddressDiscoveryReplyMessage = 145,
    MobilePrfixSolicitation = 146,
    MobilePrefixAdvertisement = 147,
    CertificationPathSolicitationMessage = 148,
    CertificationPathAdvertisementMessage = 149,
    ExperimentalMobility150 = 150,
    MulticastRouterAdvertisement = 151,
    MulticastRouterSolicitation = 152,
    MulticastRouterTermination = 153,
    FmIPv6Messages = 154,
    RplControlMessage = 155,
    IlnpV6LocatorUpdateMessage = 156,
    DuplicateAddressRequest = 157,
    DuplicateAddressConfirmation = 158,
    MplControlMessage = 159,
    ExtendedEchoRequest = 160,
    ExtendedEchoReply = 161,
    PrivateExperimentation200 = 200,
    PrivateExperimentation201 = 201,
    Reserved255 = 255,
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadIcmpV6Code {
    code: u8,
}

impl<'a> TryFrom<&'a [u8]> for PayloadIcmpV6Code{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadIcmpV6Code{
            code: cursor.read_u8().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadIcmpV6Code {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u8(self.code).unwrap();
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadIPv6NdTarget {
    target: hw_addr::IPv6Address,
}

impl<'a> TryFrom<&'a [u8]> for PayloadIPv6NdTarget{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(PayloadIPv6NdTarget{
            target: hw_addr::from_slice_v6(&bytes[..])?,
        })
    }
}

impl Into<Vec<u8>> for PayloadIPv6NdTarget {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.extend_from_slice(&self.target[..]);
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadIPv6NdSll {
    nd_sll: hw_addr::EthernetAddress,
}

impl<'a> TryFrom<&'a [u8]> for PayloadIPv6NdSll{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(PayloadIPv6NdSll{
            nd_sll: hw_addr::from_slice_eth(&bytes[..])?,
        })
    }
}

impl Into<Vec<u8>> for PayloadIPv6NdSll {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.extend_from_slice(&self.nd_sll[..]);
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadIPv6NdTll {
    nd_tll: hw_addr::EthernetAddress,
}

impl<'a> TryFrom<&'a [u8]> for PayloadIPv6NdTll{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(PayloadIPv6NdTll{
            nd_tll: hw_addr::from_slice_eth(&bytes[..])?,
        })
    }
}

impl Into<Vec<u8>> for PayloadIPv6NdTll {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.extend_from_slice(&self.nd_tll[..]);
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadMplsLabel {
    label: u32, // 20 bits
}

impl<'a> TryFrom<&'a [u8]> for PayloadMplsLabel{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadMplsLabel{
            label: cursor.read_u32::<BigEndian>().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadMplsLabel {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(self.label).unwrap();
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadMplsTc {
    tc: u8, // 3 bits
}

impl<'a> TryFrom<&'a [u8]> for PayloadMplsTc{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadMplsTc{
            tc: cursor.read_u8().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadMplsTc {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u8(self.tc).unwrap();
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadMplsBos {
    bos: u8, // 1 bits
}

impl<'a> TryFrom<&'a [u8]> for PayloadMplsBos{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadMplsBos{
            bos: cursor.read_u8().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadMplsBos {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u8(self.bos).unwrap();
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadPbbISid {
    i_sid: u32, // 24 bits
}

impl<'a> TryFrom<&'a [u8]> for PayloadPbbISid{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadPbbISid{
            i_sid: cursor.read_u32::<BigEndian>().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadPbbISid {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u32::<BigEndian>(self.i_sid).unwrap();
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadTunnelId {
    metadata: u64,
}

impl<'a> TryFrom<&'a [u8]> for PayloadTunnelId{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        Ok(PayloadTunnelId{
            metadata: cursor.read_u64::<BigEndian>().unwrap(),
        })
    }
}

impl Into<Vec<u8>> for PayloadTunnelId {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u64::<BigEndian>(self.metadata).unwrap();
        res
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PayloadIPv6ExtHdr {
    ext_hdr_flags: IPv6ExtHdrFlags, // 9 bits
}

impl<'a> TryFrom<&'a [u8]> for PayloadIPv6ExtHdr{
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let raw_flags = cursor.read_u16::<BigEndian>().unwrap();
        Ok(PayloadIPv6ExtHdr{
            ext_hdr_flags: IPv6ExtHdrFlags(raw_flags),
        })
    }
}

impl Into<Vec<u8>> for PayloadIPv6ExtHdr {
    fn into(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.write_u16::<BigEndian>(self.ext_hdr_flags.0).unwrap();
        res
    }
}

bitfield!{
    pub struct IPv6ExtHdrFlags(u16);
    impl Debug;

    u8;
    /// "No next header" encountered.
    pub get_no_next, set_no_next: 1, 0;
    /// Encrypted Sec Payload header present.
    pub get_esp, set_esp: 2, 1;
    /// Authentication header present.
    pub get_auth, set_auth: 3, 2;
    /// 1 or 2 dest headers present.
    pub get_dest, set_dest: 4, 3;
    /// Fragment header present.
    pub get_frag, set_frag: 5, 4;
    /// Router header present.
    pub get_router, set_router: 6, 5;
    /// Hop-by-hop header present.
    pub get_hop, set_hop: 7, 6;
    /// Unexpected repeats encountered.
    pub get_unrep, set_unrep: 8, 7;
    /// Unexpected sequencing encountered.
    pub get_unseq, set_unseq: 9, 8;
}

impl Clone for IPv6ExtHdrFlags{
    fn clone(&self) -> Self {
        IPv6ExtHdrFlags(self.0.clone())
    }
}

impl ::std::cmp::PartialEq for IPv6ExtHdrFlags{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
