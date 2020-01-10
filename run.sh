TARGET_NAME=sample-enclave
TARGET_DIR=target/x86_64-fortanix-unknown-sgx/debug
TARGET=$TARGET_DIR/$TARGET_NAME.sgxs
ftxsgx-runner --signature coresident $TARGET &
cargo run -p sample-client &
cargo run -p sample-sp
