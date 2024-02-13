use core::convert::From;

use psila_crypto_rust_crypto::RustCryptoBackend;
use psila_data::application_service::commands::transport_key::NetworkKey;
use psila_data::{common::key::Key, pack::Pack, security};
use ufmt::uwrite;

pub struct SecurityService {
    pub keys: heapless::Vec<Key, 16>,
    crypto_provider: security::CryptoProvider<RustCryptoBackend>,
}

impl SecurityService {
    pub fn new() -> Self {
        let mut keys: heapless::Vec<Key, 16> = heapless::Vec::new();
        let _ = keys.push(Key::from(security::DEFAULT_LINK_KEY));
        let backend = RustCryptoBackend::default();
        let crypto_provider = security::CryptoProvider::new(backend);
        SecurityService {
            keys,
            crypto_provider,
        }
    }

    fn print_header(header: &security::SecurityHeader) {
        let mut line: heapless::String<256> = heapless::String::new();

        let level = match header.control.level {
            security::SecurityLevel::None => "None",
            security::SecurityLevel::Integrity32 => "32-bitIntegrity",
            security::SecurityLevel::Integrity64 => "64-bitIntegrity",
            security::SecurityLevel::Integrity128 => "128-bitIntegrity",
            security::SecurityLevel::Encrypted => "Encrypted",
            security::SecurityLevel::EncryptedIntegrity32 => "Encrypted, 32-bit Integrity",
            security::SecurityLevel::EncryptedIntegrity64 => "Encrypted, 64-bit Integrity",
            security::SecurityLevel::EncryptedIntegrity128 => "Encrypted, 128-bit Integrity",
        };
        let identifier = match header.control.identifier {
            security::KeyIdentifier::Data => "Data",
            security::KeyIdentifier::Network => "Network",
            security::KeyIdentifier::KeyTransport => "Key transport",
            security::KeyIdentifier::KeyLoad => "Key load",
        };

        let _ = uwrite!(line, "SEC Level {} Key Identifier {}", level, identifier,);
        if let Some(src) = header.source {
            let _ = uwrite!(line, " SRC {:08x}", u64::from(src));
        }
        if let Some(seq) = header.sequence {
            let _ = uwrite!(line, " Sequence {}", seq);
        }
        let _ = uwrite!(line, " Counter {}", header.counter);
        defmt::info!("{}", line.as_str());
    }

    pub fn decrypt(&mut self, payload: &[u8], offset: usize, mut output: &mut [u8]) -> usize {
        match security::SecurityHeader::unpack(&payload[offset..]) {
            Ok((header, _)) => {
                Self::print_header(&header);
            }
            Err(ref e) => {
                crate::print_error(e, "Failed to parse security header");
                return 0;
            }
        }
        for key_index in 0..self.keys.len() {
            let key = self.keys[key_index].into();
            let result = self.crypto_provider.decrypt_payload(
                &key,
                security::SecurityLevel::EncryptedIntegrity32,
                &payload,
                offset,
                &mut output,
            );
            match result {
                Ok(size) => {
                    if size > 0 {
                        defmt::info!("~~~ KEY {}", key_index);
                        return size;
                    }
                }
                Err(_e) => (),
            }
        }
        defmt::warn!("No valid key found");
        0
    }

    pub fn add_key_bytes(&mut self, key: [u8; 16]) {
        let _ = self.keys.push(Key::from(key));
    }

    pub fn add_key(&mut self, key: Key) {
        let _ = self.keys.push(key);
    }

    pub fn add_transport_key(&mut self, new_key: &NetworkKey) {
        for key in self.keys.iter() {
            if *key == new_key.key {
                return;
            }
        }
        let _ = self.keys.push(new_key.key);
    }
}
