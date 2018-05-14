
/// length of ethernet address in bytes (6)
pub const ETHERNET_ADDRESS_LENGTH: usize = 6;
pub type EthernetAddress = [u8; ETHERNET_ADDRESS_LENGTH];

pub fn from_slice_eth(slice: &[u8]) -> EthernetAddress{
    let mut addr = [0u8; ETHERNET_ADDRESS_LENGTH];
    for i in 0..ETHERNET_ADDRESS_LENGTH{
        addr[i] = slice[i];
    }
    addr
}

/// lenght of ipv4 address in bytes (4)
pub const IPV4_ADDRESS_LENGTH: usize = 4;
pub type IPv4Address = [u8; IPV4_ADDRESS_LENGTH];

pub fn from_slice_v4(slice: &[u8]) -> IPv4Address {
    let mut addr = [0u8; IPV4_ADDRESS_LENGTH];
    for i in 0..IPV4_ADDRESS_LENGTH{
        addr[i] = slice[i];
    }
    addr
}

/// lenght of ipv6 address in bytes (8)
pub const IPV6_ADDRESS_LENGTH: usize = 8;
pub type IPv6Address = [u8; IPV6_ADDRESS_LENGTH];

pub fn from_slice_v6(slice: &[u8]) -> IPv6Address {
    let mut addr = [0u8; IPV6_ADDRESS_LENGTH];
    for i in 0..IPV6_ADDRESS_LENGTH{
        addr[i] = slice[i];
    }
    addr
}
