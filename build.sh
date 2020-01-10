# build and sign enclave
cargo build -p sample-enclave --target x86_64-fortanix-unknown-sgx
TARGET_NAME=sample-enclave
TARGET_DIR=target/x86_64-fortanix-unknown-sgx/debug
TARGET=$TARGET_DIR/$TARGET_NAME
TARGET_SGX=$TARGET_DIR/$TARGET_NAME.sgxs
TARGET_SIG=$TARGET_DIR/$TARGET_NAME.sig
KEY=sample-enclave/data/vendor-keys/private_key.pem
ftxsgx-elf2sgxs $TARGET --heap-size 0x2000000 --stack-size 0x20000 --threads 8 \
    --debug --output $TARGET_SGX
sgxs-sign --key $KEY $TARGET_SGX $TARGET_SIG -d --xfrm 7/0 --isvprodid 0 --isvsvn 0
cargo build -p sample-client
cargo build -p sample-sp

