use crate::{MacAddress, error::FormatError};

#[derive(Debug, Clone, Copy)]
pub enum PingOutcome {
    // The remote host (<ip>) is considered as dead - not scanning
    // The remote host (<ip>) did not respond to the following ping methods :
    // - TCP ping
    // - ICMP ping
    HostDidntRespondToPingMethods { tcp: bool, icmp: bool },
    // The remote host replied to an ICMP echo packet
    IcmpEchoPacket,
    // The remote host (<ip>) is considered as dead - not scanning
    // The remote host ('<ip>') is on the local network and failed to reply to an ARP who-is query.
    HostLocalNetworkDidntRespondArpWhoIsQuery,
    ArpWhoIsQuery(MacAddress),
    // The remote host replied with an ICMP unreach packet sent in response to a TCP SYN packet sent to port <u16>
    IcmpUnreachPacketInResponseToTcpSynPacket { to: u16 },
    // The remote host replied to a TCP SYN packet sent to port <u16> with a RST,ACK packet
    RepliedTcpSynPacketWithRstAck { to: u16 },
    // The remote host replied to a TCP SYN packet sent to port <u16> with a SYN,ACK packet
    RepliedTcpSynPacketWithSynAck { to: u16 },
    // The remote host emitted a TCP SYN packet from port <u16> going to port <u16>
    EmittedTcpSynPacket { from: u16, to: u16 },
    // The remote host replied with an ICMP unreach packet.
    IcmpUnreachPacket,
    // The remote host emited a UDP packet from port <u16> going to port <u16>
    EmittedUdpPacket { from: u16, to: u16 },
    // The host is the local scanner.
    LocalScanner,
}

impl PingOutcome {
    pub(crate) fn from_plugin_output(plugin_output: &str) -> Result<Self, FormatError> {
        const LOCAL_SCANNER: &str = "The remote host is up\nThe host is the local scanner.";
        const ICMP_ECHO_PACKET: &str =
            "The remote host is up\nThe remote host replied to an ICMP echo packet";
        const ICMP_UNREACH_PACKET: &str =
            "The remote host is up\nThe remote host replied with an ICMP unreach packet.";
        const ARP_WHO_IS_QUERY_PREFIX: &str =
            "The remote host is up\nThe host replied to an ARP who-is query.\nHardware address : ";
        const REPLIED_TCP_SYN_PACKET_PREFIX: &str =
            "The remote host is up\nThe remote host replied to a TCP SYN packet sent to port ";
        const WITH_RST_ACK_SUFFIX: &str = " with a RST,ACK packet";
        const WITH_SYN_ACK_SUFFIX: &str = " with a SYN,ACK packet";
        const ICMP_UNREACH_PACKET_RESPONSE_TO_TCP_SYN_PACKET_PREFIX: &str = "The remote host is up\nThe remote host replied with an ICMP unreach packet sent in response to a TCP SYN packet sent to port ";
        const EMITTED_UDP_PACKET_PREFIX: &str =
            "The remote host is up\nThe remote host emited a UDP packet from port ";
        const EMITTED_PACKET_MIDDLE: &str = "going to port ";
        const EMITTED_TCP_SYN_PACKET_PREFIX: &str =
            "The remote host is up\nThe remote host emitted a TCP SYN packet from port ";
        const DEAD_HOST_NEEDLE: &str = ") is considered as dead - not scanning\nThe remote host (";
        const FAILED_TO_REPLY_ARP_SUFFIX: &str =
            ") is on the local network and failed to reply to an ARP who-is query.";
        const DIDNT_RESPOND_TO_PING_METHODS_NEEDLE: &str =
            ") did not respond to the following ping methods :\n";

        match plugin_output {
            ICMP_ECHO_PACKET => Ok(Self::IcmpEchoPacket),
            LOCAL_SCANNER => Ok(Self::LocalScanner),
            ICMP_UNREACH_PACKET => Ok(Self::IcmpUnreachPacket),
            text => {
                if text.contains(DEAD_HOST_NEEDLE) {
                    if text.ends_with(FAILED_TO_REPLY_ARP_SUFFIX) {
                        Ok(Self::HostLocalNetworkDidntRespondArpWhoIsQuery)
                    } else if let Some((_, ping_methods)) =
                        text.split_once(DIDNT_RESPOND_TO_PING_METHODS_NEEDLE)
                    {
                        let mut tcp = false;
                        let mut icmp = false;
                        for ping_method in ping_methods.trim_end().split('\n') {
                            match ping_method {
                                "- TCP ping" => tcp = true,
                                "- ICMP ping" => icmp = true,
                                _ => {
                                    return Err(FormatError::UnexpectedPingMethod(
                                        plugin_output.into(),
                                    ));
                                }
                            }
                        }
                        if !tcp && !icmp {
                            Err(FormatError::UnexpectedPingFormat(plugin_output.into()))
                        } else {
                            Ok(Self::HostDidntRespondToPingMethods { tcp, icmp })
                        }
                    } else {
                        Err(FormatError::UnexpectedDeadHostReason(plugin_output.into()))
                    }
                } else if let Some(mac) = text.strip_prefix(ARP_WHO_IS_QUERY_PREFIX) {
                    Ok(Self::ArpWhoIsQuery(mac.parse()?))
                } else if let Some(port) =
                    text.strip_prefix(ICMP_UNREACH_PACKET_RESPONSE_TO_TCP_SYN_PACKET_PREFIX)
                {
                    Ok(Self::IcmpUnreachPacketInResponseToTcpSynPacket { to: port.parse()? })
                } else if let Some(port_and_suffix) =
                    text.strip_prefix(REPLIED_TCP_SYN_PACKET_PREFIX)
                {
                    if let Some(port) = port_and_suffix.strip_suffix(WITH_RST_ACK_SUFFIX) {
                        Ok(Self::RepliedTcpSynPacketWithRstAck { to: port.parse()? })
                    } else if let Some(port) = port_and_suffix.strip_suffix(WITH_SYN_ACK_SUFFIX) {
                        Ok(Self::RepliedTcpSynPacketWithSynAck { to: port.parse()? })
                    } else {
                        Err(FormatError::UnexpectedPingTcpResponse(plugin_output.into()))
                    }
                } else if let Some(from_port_and_rest) =
                    text.strip_prefix(EMITTED_TCP_SYN_PACKET_PREFIX)
                    && let Some((from_port, rest)) = from_port_and_rest.split_once(' ')
                    && let Some(to_port) = rest.strip_prefix(EMITTED_PACKET_MIDDLE)
                {
                    Ok(Self::EmittedTcpSynPacket {
                        from: from_port.parse()?,
                        to: to_port.parse()?,
                    })
                } else if let Some(from_port_and_rest) =
                    text.strip_prefix(EMITTED_UDP_PACKET_PREFIX)
                    && let Some((from_port, rest)) = from_port_and_rest.split_once(' ')
                    && let Some(to_port) = rest.strip_prefix(EMITTED_PACKET_MIDDLE)
                {
                    Ok(Self::EmittedUdpPacket {
                        from: from_port.parse()?,
                        to: to_port.parse()?,
                    })
                } else {
                    Err(FormatError::UnexpectedPingFormat(plugin_output.into()))
                }
            }
        }
    }
}
