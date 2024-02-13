#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

use byte::BytesExt;
use defmt;
use embassy_executor::Spawner;
use esp_backtrace as _;
use esp_ieee802154;
use hal::{clock::ClockControl, embassy, peripherals::Peripherals, prelude::*, timer::TimerGroup};
use ieee802154::mac::{self, FooterMode};

use psila_data::common::key::Key;

use esp32c6_psila::Parser;

const NETWORK_KEY: &str = env!("NETWORK_KEY");

fn key_from_str(s: &str) -> Result<Key, ()> {
    if s.len() != 32 {
        return Err(());
    }
    let mut offset = 0;
    let mut key = [0u8; 16];
    for byte in key.iter_mut().take(16) {
        *byte = match u8::from_str_radix(&s[offset..offset + 2], 16) {
            Ok(v) => v,
            Err(_) => return Err(()),
        };
        offset += 2;
    }
    Ok(Key::from(key))
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
        channel: 25,
        promiscuous: true,
        rx_when_idle: true,
        auto_ack_rx: false,
        auto_ack_tx: false,
        ..esp_ieee802154::Config::default()
    });

    embassy::init(&clocks, timer_group0);

    let mut parser = Parser::new();

    match key_from_str(NETWORK_KEY) {
        Ok(key) => {
            defmt::info!("Added network key");
            parser.security.add_key(key);
        }
        Err(_) => (),
    }

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
                    parser.parse_802154_mac(&frame);
                }
                Err(_) => {
                    defmt::error!("Failed to receive frame\n");
                }
            }
        }
    }
}
