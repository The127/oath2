#[derive(Debug)]
pub struct MultipartRequest {
    ttype: MultipartTypes,
    flags: bool,
    // pad 4 bytes
    payload: ReqPayload,
}

#[derive(PartialEq, Debug, Clone)]
pub enum ReqPayload {
    Desc,
}

#[derive(Debug)]
pub struct MultipartReply {
    ttype: MultipartTypes,
    flags: u16,
    // pad 4 bytes
    payload: RepPayload,
}

#[derive(PartialEq, Debug, Clone)]
pub enum RepPayload {
    Desc(RepDesc),
}

#[derive(PartialEq, Debug, Clone)]
pub struct RepDesc {}

#[derive(Primitive, PartialEq, Debug, Clone)]
enum MultipartTypes {
    /// Description of this OpenFlow switch.
    /// The request body is empty.
    /// The reply body is struct ofp_desc.
    Desc = 0,
    /// Individual flow statistics.
    /// The request body is struct ofp_flow_stats_request.
    /// The reply body is an array of struct ofp_flow_stats.
    Flow = 1,
    /// Aggregate flow statistics.
    /// The request body is struct ofp_aggregate_stats_request.
    /// The reply body is struct ofp_aggregate_stats_reply.
    Aggregate = 2,
    /// Flow table statistics.
    /// The request body is empty.
    /// The reply body is an array of struct ofp_table_stats.
    Table = 3,
    /// Port statistics.
    /// The request body is struct ofp_port_stats_request.
    /// The reply body is an array of struct ofp_port_stats.
    PortStats = 4,
    /// Queue statistics for a port
    /// The request body is struct ofp_queue_stats_request.
    /// The reply body is an array of struct ofp_queue_stats
    Queue = 5,
    /// Group counter statistics.
    /// The request body is struct ofp_group_stats_request.
    /// The reply is an array of struct ofp_group_stats.
    Group = 6,
    /// Group description.
    /// The request body is empty.
    /// The reply body is an array of struct ofp_group_desc_stats.
    GroupDesc = 7,
    /// Group features.
    /// The request body is empty.
    /// The reply body is struct ofp_group_features.
    GroupFeatures = 8,
    /// Meter statistics.
    /// The request body is struct ofp_meter_multipart_requests.
    /// The reply body is an array of struct ofp_meter_stats.
    Meter = 9,
    /// Meter configuration.
    /// The request body is struct ofp_meter_multipart_requests.
    /// The reply body is an array of struct ofp_meter_config.
    MeterConfig = 10,
    /// Meter features.
    /// The request body is empty.
    /// The reply body is struct ofp_meter_features.
    MeterFeatures = 11,
    /// Table features.
    /// The request body is either empty or contains an array of
    /// struct ofp_table_features containing the controller's
    /// desired view of the switch. If the switch is unable to
    /// set the specified view an error is returned.
    /// The reply body is an array of struct ofp_table_features.
    TableFeatures = 12,
    /// Port description.
    /// The request body is empty.
    /// The reply body is an array of struct ofp_port.
    PortDesc = 13,
    /// Experimenter extension.
    /// The request and reply bodies begin with
    /// struct ofp_experimenter_multipart_header.
    /// The request and reply bodies are otherwise experimenter-defined.
    Experimenter = 0xffff,
}
