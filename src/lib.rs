#![no_std]

mod parser;
mod security;

pub fn print_error(error: &psila_data::Error, message: &str) {
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

pub use parser::Parser;
pub use security::SecurityService;
