TARGET_NAME=sample-enclave
TARGET_DIR=$TARGET_NAME/target/x86_64-fortanix-unknown-sgx/debug
TARGET=$TARGET_DIR/$TARGET_NAME.sgxs

# Run enclave with the default runner
ftxsgx-runner --signature coresident $TARGET &

# Run client
(cd sample-client && cargo run) &

# Run SP
(cd sample-sp && cargo run)
