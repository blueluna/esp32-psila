# Psila on ESP32C6

### Build

Requires a fairly modern version of Rust. See https://rustup.rs for installation.

Some configuration is applied from environment variables during the build.
- NETWORK_KEY, Optional, A network key used to decrypt secure payload. 16-bit hexadecimal, i.e. `fedcba9876543210fedcba9876543210`.

```shell
NETWORK_KEY=<NETWORK_KEY> cargo build --examples
```

### Flash and run

Running the firmware on target requires espflash. See https://crates.io/crates/cargo-espflash. Using the git version
```shell
cargo install -f --git https://github.com/esp-rs/espflash espflash
```

Run similar to the build step.

```shell
NETWORK_KEY=<NETWORK_KEY> cargo run --example listener
```
