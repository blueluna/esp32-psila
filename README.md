# Psila on ESP32C6

### Build

Requires a fairly modern version of Rust. See https://rustup.rs for installation.

```shell
cargo build
```

### Flash and run

Running the firmware on target requires espflash. See https://crates.io/crates/cargo-espflash. Using the git version
```shell
cargo install -f --git https://github.com/esp-rs/espflash espflash
```

Run similar to the build step.

```shell
cargo run
```
