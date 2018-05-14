

/// defines an OpenFlow message
/// header + payload
#[derive(Getters, Debug)]
pub struct OfMsg {
    #[get = "pub"]
    header: Header,
    #[get = "pub"]
    payload: (),
}

/// OpenFlow message header length is 8 bytes.
pub const HEADER_LENGTH: usize = 8;

/// OpenFlow header struct.
#[derive(Getters, Debug, PartialEq, Clone)]
pub struct Header {
    /// OpenFlow version identifier
    #[get = "pub"]
    version: Version,
    /// OpenFlow message  type
    #[get = "pub"]
    ttype: Type,
    /// length of message including this header
    #[get = "pub"]
    length: u16,
    /// Transaction id associated with this packet.
    /// Replies use the same id as was in the request
    /// to facilitate pairing.
    #[get = "pub"]
    xid: u32,
}

/// OpenFlow Version enum.
#[derive(Primitive, PartialEq, Debug, Clone)]
pub enum Version {
    /// indicates OpenFlow version 1.0
    V1_0 = 0x01,
    /// indicates OpenFlow version 1.1
    V1_1 = 0x02,
    /// indicates OpenFlow version 1.2
    V1_2 = 0x03,
    /// indicates OpenFlow version 1.3
    V1_3 = 0x04,
    /// indicates OpenFlow version 1.4
    V1_4 = 0x05,
}

/// Enum of OpenFlow message types.
#[derive(Primitive, PartialEq, Debug, Clone)]
pub enum Type {
    /* Immutable messages. */
    /// Hello message sent by switch and controller 
    /// directly after establishing a connection.
    /// Symmetric message.
    Hello = 0, 
    /// Symmetric message 
    Error = 1, 
    /// Symmetric message 
    EchoRequest = 2, 
    /// Symmetric message 
    EchoReply = 3, 
    /// Symmetric message 
    Experimenter = 4,

    /* Switch configuration messages. */
    /// Controller/switch message 
    FeaturesRequest = 5, 
    /// Controller/switch message 
    FeaturesReply = 6, 
    /// Controller/switch message 
    GetConfigRequest = 7, 
    /// Controller/switch message 
    GetConfigReply = 8, 
    /// Controller/switch message 
    SetConfig = 9, 

    /* Asynchronous messages. */
    /// Async message 
    PacketIn = 10, 
    /// Async message 
    FlowRemoved = 11, 
    /// Async message 
    PortStatus = 12, 

    /* Controller command messages. */
    /// Controller/switch message 
    PacketOut = 13,
    /// Controller/switch message 
    FlowMod = 14, 
    /// Controller/switch message 
    GroupMod = 15,
    /// Controller/switch message  
    PortMod = 16, 
    /// Controller/switch message 
    TableMod = 17, 

    /* Multipart messages. */
    /// Controller/switch message 
    MultipartRequest = 18, 
    /// Controller/switch message 
    MultipartReply = 19, 

    /* Barrier messages. */
    /// Controller/switch message 
    BarrierRequest = 20, 
    /// Controller/switch message 
    BarrierReply = 21, 

    /* Queue Configuration messages. */
    /// Controller/switch message 
    QueueGetConfigRequest = 22, 
    /// Controller/switch message 
    QueueGetConfigReply = 23, 
    /* Controller role change request messages. */
    /// Controller/switch message 
    RoleRequest = 24, 
    /// Controller/switch message 
    RoleReply = 25, 

    /* Asynchronous message configuration.  */
    /// Controller/switch message 
    GetAsyncRequest = 26, 
    /// Controller/switch message 
    GetAsyncReply = 27, 
    /// Controller/switch message 
    SetAsync = 28, 

    /* Meters and rate limiters configuration messages. */
    /// Controller/switch message 
    MeterMod = 29, 
}