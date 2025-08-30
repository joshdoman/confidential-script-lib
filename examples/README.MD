# Covenants Example

> **Experimental build using [`bitcoinkernel-covenants`](https://github.com/stutxo/rust-bitcoinkernel-covenants)** with OP_CAT, OP_CSFS and OP_CTV enabled
> Not intended for production use. Use at your own risk.

## Run Tests

```bash
cargo test
```

## Build Docker Image for Nitro Enclave

```bash
docker build -f Dockerfile.example -t covenants-example .
```

## Build and Run Nitro Enclave

```bash
# Build the enclave image
nitro-cli build-enclave \
  --docker-uri covenants-example \
  --output-file covenants_example.eif

# Run the enclave with specified CPU, memory, and CID
nitro-cli run-enclave \
  --cpu-count 2 \
  --memory 512 \
  --enclave-cid 16 \
  --eif-path covenants_example.eif \
  --debug-mode

# Inspect running enclaves
nitro-cli describe-enclaves

# Connect to the enclave console (replace <id> with the Enclave ID)
nitro-cli console --enclave-id <id>
```
