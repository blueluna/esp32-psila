use defmt;
use ieee802154::mac::{self, beacon::BeaconOrder};
use psila_data::{
    network::{self, NetworkHeader},
    pack::Pack,
};
use ufmt::uwrite;

use crate::security::SecurityService;

pub struct Parser {
    pub security: SecurityService,
}

impl Parser {
    pub fn new() -> Self {
        Parser {
            security: SecurityService::new(),
        }
    }

    fn parse_network_command(&self, payload: &[u8]) {
        use network::commands::Command;
        let mut line: heapless::String<256> = heapless::String::new();
        let _ = uwrite!(line, "NWK CMD ",);
        match Command::unpack(payload) {
            Ok((cmd, _used)) => match cmd {
                Command::RouteRequest(rr) => {
                    let many = match rr.options.many_to_one {
                        network::commands::ManyToOne::No => "One to one",
                        network::commands::ManyToOne::RouteRequestTableSupport => {
                            "Many to one, table"
                        }
                        network::commands::ManyToOne::NoRouteRequestTableSupport => "Many to one",
                    };
                    let _ = uwrite!(
                        line,
                        "Route Request {:02x} Cost {} {}",
                        rr.identifier,
                        rr.path_cost,
                        many
                    );
                    match rr.destination_address {
                        network::commands::AddressType::Singlecast(a) => {
                            let _ = uwrite!(line, " Destination {:04x}", u16::from(a));
                        }
                        network::commands::AddressType::Multicast(a) => {
                            let _ = uwrite!(line, " Group {:04x}", u16::from(a));
                        }
                    }
                    if let Some(address) = rr.destination_ieee_address {
                        let _ = uwrite!(line, " Destination {:08x}", u64::from(address));
                    }
                }
                Command::RouteReply(rr) => {
                    let _ = uwrite!(
                        line,
                        "Route Reply Identifier {:02x} Originator {:04x} Responder {:04x} Path cost {}",
                        rr.identifier,
                        u16::from(rr.orginator_address),
                        u16::from(rr.responder_address),
                        rr.path_cost
                    );
                    if let Some(address) = rr.orginator_ieee_address {
                        let _ = uwrite!(line, " Originator {:04x}", u64::from(address));
                    }
                    if let Some(address) = rr.responder_ieee_address {
                        let _ = uwrite!(line, " Responder {:08x}", u64::from(address));
                    }
                }
                Command::NetworkStatus(ns) => {
                    let _ = uwrite!(
                        line,
                        "Network Status Destination {:04x} Status {:02x}",
                        u16::from(ns.destination),
                        u8::from(ns.status)
                    );
                }
                Command::Leave(leave) => {
                    let _ = uwrite!(
                        line,
                        "Leave {}{}{}",
                        if leave.rejoin { "Rejoin " } else { "" },
                        if leave.request { "Request " } else { "" },
                        if leave.remove_children {
                            "Remove children "
                        } else {
                            ""
                        },
                    );
                }
                Command::RouteRecord(rr) => {
                    let _ = uwrite!(line, "Route Record ");
                    for address in rr.entries() {
                        let _ = uwrite!(line, "{:04x} ", u16::from(*address));
                    }
                }
                Command::RejoinRequest(_rr) => {
                    let _ = uwrite!(line, "Rejoin Request");
                }
                Command::RejoinResponse(_rr) => {
                    let _ = uwrite!(line, "Rejoin Response");
                }
                Command::LinkStatus(ls) => {
                    let _ = uwrite!(line, "Link Status ");
                    if ls.first_frame && !ls.last_frame {
                        let _ = uwrite!(line, "First ");
                    } else if !ls.first_frame && ls.last_frame {
                        let _ = uwrite!(line, "Last ");
                    }
                    for entry in ls.entries() {
                        let _ = uwrite!(
                            line,
                            "{:04x} Incoming {} Outgoing {} ",
                            u16::from(entry.address),
                            entry.incoming_cost,
                            entry.outgoing_cost
                        );
                    }
                }
                Command::NetworkReport(nr) => {
                    let _ = uwrite!(
                        line,
                        "Network Conflict {:08x} {:04x}",
                        u64::from(nr.extended_pan_identifier),
                        u16::from(nr.pan_identifier)
                    );
                }
                Command::NetworkUpdate(nu) => {
                    let _ = uwrite!(
                        line,
                        "Network Update {:08x} {:04x}",
                        u64::from(nu.extended_pan_identifier),
                        u16::from(nu.pan_identifier)
                    );
                }
                Command::EndDeviceTimeoutRequest(edtr) => {
                    let _ = uwrite!(
                        line,
                        "End-device Timeout Request, Timeout {}s",
                        edtr.timeout.in_seconds()
                    );
                }
                Command::EndDeviceTimeoutResponse(edtr) => {

                    let _ = uwrite!(
                        line,
                        "End-device Timeout Response, {} {} {}",
                        u8::from(edtr.status),
                        if edtr.mac_keep_alive {
                            "MAC keep alive"
                        } else {
                            ""
                        },
                        if edtr.end_device_keep_alive {
                            "End device keep alive"
                        } else {
                            ""
                        },
                    );
                }
            },
            Err(ref e) => {
                crate::print_error(e, "Failed to decode network command");
            }
        }
        defmt::info!("{}", line.as_str());
    }

    fn parse_network_frame(&mut self, payload: &[u8]) {
        let mut line: heapless::String<256> = heapless::String::new();

        match NetworkHeader::unpack(payload) {
            Ok((network_frame, used)) => {
                let frame_type = match network_frame.control.frame_type {
                    network::header::FrameType::Command => "Command",
                    network::header::FrameType::Data => "Data",
                    network::header::FrameType::InterPan => "Inter-PAN",
                };
                let discovery = match network_frame.control.discover_route {
                    network::header::DiscoverRoute::EnableDiscovery => " DSC",
                    network::header::DiscoverRoute::SuppressDiscovery => "",
                };
                let security = if network_frame.control.security {
                    " SEC"
                } else {
                    ""
                };
                let _ = uwrite!(
                    line,
                    "NWK {} VER {}{}{} DST {:04x} SRC {:04x} RAD {} SEQ {}",
                    frame_type,
                    network_frame.control.protocol_version,
                    discovery,
                    security,
                    u16::from(network_frame.destination_address),
                    u16::from(network_frame.source_address),
                    network_frame.radius,
                    network_frame.sequence_number,
                );
                if let Some(dst) = network_frame.destination_ieee_address {
                    let _ = uwrite!(line, " DST {:08x}", u64::from(dst));
                }
                if let Some(src) = network_frame.source_ieee_address {
                    let _ = uwrite!(line, " SRC {:08x}", u64::from(src));
                }
                if let Some(mc) = network_frame.multicast_control {
                    let mode = match mc.mode {
                        network::header::MulticastMode::NonmemberMode => "non-member",
                        network::header::MulticastMode::MemberMode => "member",
                    };
                    let _ = uwrite!(line, " MC {} RAD {} MAX {}", mode, mc.radius, mc.max_radius);
                }
                if let Some(srf) = network_frame.source_route_frame {
                    let _ = uwrite!(line, " SRF I {}", srf.index);
                    for address in srf.entries() {
                        let _ = uwrite!(line, " {:04x}", u16::from(*address));
                    }
                }
                defmt::info!("{}", line.as_str());

                let mut processed_payload = [0u8; 256];
                let length = if network_frame.control.security {
                    self.security
                        .decrypt(&payload, used, &mut processed_payload)
                } else {
                    let length = payload.len() - used;
                    processed_payload[..length].copy_from_slice(&payload[used..]);
                    length
                };
                if length > 0 {
                    match network_frame.control.frame_type {
                        network::header::FrameType::Data | network::header::FrameType::InterPan => {
                            // self.parse_application_service_frame(&processed_payload[..length])
                        }
                        network::header::FrameType::Command => {
                            self.parse_network_command(&processed_payload[..length]);
                        }
                    }
                }
            }
            Err(ref e) => {
                crate::print_error(e, "Failed to decode network frame");
            }
        }
    }

    pub fn parse_802154_mac(&mut self, frame: &ieee802154::mac::Frame) {
        let mut line: heapless::String<256> = heapless::String::new();

        let frame_type = match frame.header.frame_type {
            mac::FrameType::Acknowledgement => "Acknowledgement",
            mac::FrameType::Beacon => "Beacon",
            mac::FrameType::Data => "Data",
            mac::FrameType::MacCommand => "Command",
            mac::FrameType::Multipurpose => "Multipurpose",
            mac::FrameType::FragOrFragAck => "Fragment",
            mac::FrameType::Extended => "Extended",
        };
        let _ = uwrite!(&mut line, "802.15.4 TYPE: {}", frame_type);
        if frame.header.frame_pending {
            let _ = uwrite!(&mut line, " PEND");
        }
        if frame.header.ack_request {
            let _ = uwrite!(&mut line, " ACK");
        }
        if frame.header.pan_id_compress {
            let _ = uwrite!(&mut line, " CMPR");
        }
        let _ = uwrite!(&mut line, " SEQ: {}", frame.header.seq);
        match frame.header.destination {
            Some(mac::Address::Short(i, a)) => {
                let _ = uwrite!(&mut line, " DST: {:04x}:{:04x}", i.0, a.0);
            }
            Some(mac::Address::Extended(i, a)) => {
                let _ = uwrite!(&mut line, " DST: {:04x}:{:016x}", i.0, a.0);
            }
            None => (),
        }
        match frame.header.source {
            Some(mac::Address::Short(i, a)) => {
                let _ = uwrite!(&mut line, " SRC: {:04x}:{:04x}", i.0, a.0);
            }
            Some(mac::Address::Extended(i, a)) => {
                let _ = uwrite!(&mut line, " SRC: {:04x}:{:016x}", i.0, a.0);
            }
            None => (),
        }
        match frame.content {
            mac::FrameContent::Acknowledgement => {
                // Nothing here
            }
            mac::FrameContent::Beacon(beacon) => {
                let _ = uwrite!(&mut line, " Beacon ");
                match beacon.superframe_spec.beacon_order {
                    BeaconOrder::OnDemand => {
                        let _ = uwrite!(&mut line, "on-demand ");
                    }
                    BeaconOrder::BeaconOrder(value) => {
                        let _ = uwrite!(&mut line, "order {}", value);
                    }
                }
                let coordinator = if beacon.superframe_spec.pan_coordinator {
                    "Coordinator"
                } else {
                    "Device"
                };
                let association_permit = if beacon.superframe_spec.association_permit {
                    "Permit association"
                } else {
                    "Deny association"
                };
                let _ = uwrite!(&mut line, "{} {}", coordinator, association_permit);
                if beacon.superframe_spec.battery_life_extension {
                    let _ = uwrite!(&mut line, "Battery life extension");
                }
                if beacon.guaranteed_time_slot_info.permit {
                    let _ = uwrite!(
                        &mut line,
                        "GTS slots {}",
                        beacon.guaranteed_time_slot_info.slots().len()
                    );
                }
            }
            mac::FrameContent::Data => (),
            mac::FrameContent::Command(command) => {
                let _ = uwrite!(&mut line, " Command ");
                match command {
                    mac::command::Command::AssociationRequest(cmd) => {
                        let _ = uwrite!(&mut line, "Association request ");
                        if cmd.full_function_device {
                            let _ = uwrite!(&mut line, "FFD ");
                        } else {
                            let _ = uwrite!(&mut line, "RFD ");
                        }
                        if cmd.mains_power {
                            let _ = uwrite!(&mut line, "Mains power ");
                        }
                        if cmd.idle_receive {
                            let _ = uwrite!(&mut line, "Idle Rx ");
                        }
                        if cmd.frame_protection {
                            let _ = uwrite!(&mut line, "Secure ");
                        }
                        if cmd.allocate_address {
                            let _ = uwrite!(&mut line, "Allocate address ");
                        }
                    }
                    mac::command::Command::AssociationResponse(address, _status) => {
                        let _ = uwrite!(&mut line, " Association response {:04x}", address.0);
                    }
                    mac::command::Command::DisassociationNotification(reason) => {
                        let reason = match reason {
                            mac::command::DisassociationReason::CoordinatorLeave => {
                                "requested to leave"
                            }
                            mac::command::DisassociationReason::DeviceLeave => "leave",
                        };
                        let _ = uwrite!(&mut line, " Disassociation {}", reason);
                    }
                    mac::command::Command::BeaconRequest => {
                        let _ = uwrite!(&mut line, " Beacon request");
                    }
                    mac::command::Command::DataRequest => {
                        let _ = uwrite!(&mut line, " Data request");
                    }
                    _ => {
                        let _ = uwrite!(&mut line, " Other command");
                    }
                }
            }
            mac::FrameContent::Multipurpose => (),
            mac::FrameContent::FragOrFragAck => (),
            mac::FrameContent::Extended => (),
        }
        defmt::info!("{}", line.as_str());
        match frame.content {
            mac::FrameContent::Data => {
                self.parse_network_frame(frame.payload);
            }
            _ => (),
        }
    }
}
