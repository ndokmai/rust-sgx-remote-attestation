TARGET_NAME=sample-enclave
TARGET_DIR=$TARGET_NAME/target/x86_64-fortanix-unknown-sgx/debug
TARGET=$TARGET_DIR/$TARGET_NAME.sgxs

ftxsgx-runner --signature coresident $TARGET &
(cd sample-client && cargo run) &
(cd sample-sp && cargo run)
