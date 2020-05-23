TARGET_NAME=tls-enclave
TARGET_DIR=ra-enclave/target/x86_64-fortanix-unknown-sgx/debug/examples
TARGET=$TARGET_DIR/$TARGET_NAME.sgxs

# Run enclave with the default runner
ftxsgx-runner --signature coresident $TARGET &

# Run client
(cd ra-client && cargo run -Zfeatures=itarget --example tls-client --features verbose) &

# Run SP
(cd ra-sp && cargo run -Zfeatures=itarget --example tls-sp --features "verbose")
