TARGET_NAME=sample-enclave
TARGET_DIR=$TARGET_NAME/target/x86_64-fortanix-unknown-sgx/debug
TARGET=$TARGET_DIR/$TARGET_NAME
TARGET_SGX=$TARGET_DIR/$TARGET_NAME.sgxs
TARGET_SIG=$TARGET_DIR/$TARGET_NAME.sig
KEY=$TARGET_NAME/data/vendor-keys/private_key.pem

export LLVM_CONFIG_PATH=/home/ndokmai/workspace/clang/clang+llvm-3.8.0-x86_64-linux-gnu-ubuntu-16.04/bin/llvm-config
export LD_LIBRARY_PATH=/home/ndokmai/workspace/clang/clang+llvm-3.8.0-x86_64-linux-gnu-ubuntu-16.04/lib

# Build and sign enclave
(cd sample-enclave && RUSTFLAGS="-C target-feature=+aes,+pclmul" cargo build --target x86_64-fortanix-unknown-sgx -Zfeatures=itarget) && \
ftxsgx-elf2sgxs $TARGET --heap-size 0x2000000 --stack-size 0x20000 --threads 8 \
    --debug --output $TARGET_SGX && \
sgxs-sign --key $KEY $TARGET_SGX $TARGET_SIG -d --xfrm 7/0 --isvprodid 0 --isvsvn 0

# Build client
(cd sample-client && cargo build -Zfeatures=itarget)

# Build SP
(cd sample-sp && cargo build -Zfeatures=itarget)

