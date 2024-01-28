#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

use byte::BytesExt;
use defmt;
use embassy_executor::Spawner;
use esp_backtrace as _;
use esp_ieee802154;
use hal::{clock::ClockControl, embassy, peripherals::Peripherals, prelude::*, timer::TimerGroup};
use ieee802154::mac::{self, beacon::BeaconOrder, FooterMode};
use psila_data::{
    network::{self, NetworkHeader},
    pack::Pack,
};
use ufmt::uwrite;

fn print_error(error: &psila_data::Error, message: &str) {
    let error_message = match error {
        psila_data::Error::NotEnoughSpace => "Not enough space",
        psila_data::Error::WrongNumberOfBytes => "Wrong number of bytes",
        psila_data::Error::InvalidValue => "Invalid value",
        psila_data::Error::NotImplemented => "Not implemented",
        psila_data::Error::NoShortAddress => "No short address",
        psila_data::Error::NoExtendedAddress => "No extended address",
        psila_data::Error::UnknownFrameType => "Unknown frame type",
        psila_data::Error::BrokenRelayList => "Broken relay list",
        psila_data::Error::UnknownNetworkCommand => "Unknown network command",
        psila_data::Error::UnknownDeliveryMode => "Unknown delivery mode",
        psila_data::Error::UnknownSecurityLevel => "Unknown security level",
        psila_data::Error::UnknownKeyIdentifier => "Unknown key identifier",
        psila_data::Error::UnknownApplicationCommandIdentifier => {
            "Unknown application command identifier"
        }
        psila_data::Error::UnknownDiscoverRoute => "Unknown discovery route",
        psila_data::Error::UnknownClusterIdentifier => "Unknown cluster identifier",
        psila_data::Error::UnsupportedAttributeValue => "Unsupported attribute value",
        psila_data::Error::CryptoError(_) => "Crypto error",
    };
    defmt::error!("{}, {}", message, error_message);
}

fn parse_network_frame(payload: &[u8]) {
    let mut line: heapless::String<256> = heapless::String::new();

    match NetworkHeader::unpack(payload) {
        Ok((network_frame, _used)) => {
            let frame_type = match network_frame.control.frame_type {
                network::header::FrameType::Command => "Command",
                network::header::FrameType::Data => "Data",
                network::header::FrameType::InterPan => "Interpan",
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
        }
        Err(ref e) => {
            print_error(e, "Failed to decode network frame");
        }
    }
}

fn parse_802154_mac(frame: &ieee802154::mac::Frame) {
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
            parse_network_frame(frame.payload);
        }
        _ => (),
    }
}

#[main]
async fn main(_spawner: Spawner) -> ! {
    let peripherals = Peripherals::take();
    let mut system = peripherals.SYSTEM.split();

    let clocks = ClockControl::max(system.clock_control).freeze();
    let timer_group0 = TimerGroup::new(peripherals.TIMG0, &clocks);

    let radio = peripherals.IEEE802154;
    let mut ieee802154 = esp_ieee802154::Ieee802154::new(radio, &mut system.radio_clock_control);

    ieee802154.set_config(esp_ieee802154::Config {
        channel: 11,
        promiscuous: true,
        rx_when_idle: true,
        auto_ack_rx: false,
        auto_ack_tx: false,
        ..esp_ieee802154::Config::default()
    });

    embassy::init(&clocks, timer_group0);

    defmt::info!("start receiving");
    ieee802154.start_receive();

    loop {
        if let Some(received) = ieee802154.get_raw_received() {
            let size = usize::from(received.data[0]);
            let _rssi = usize::from(received.data[size]);
            let part = &received.data[1..(size - 1)];
            defmt::info!("Received {=[u8]:02x}\n", part);
            match part.read_with::<mac::Frame>(&mut 0, FooterMode::None) {
                Ok(frame) => {
                    parse_802154_mac(&frame);
                }
                Err(_) => {
                    defmt::error!("Failed to receive frame\n");
                }
            }
        }
    }
}
