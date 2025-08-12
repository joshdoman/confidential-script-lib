# confidential-script-lib

`confidential-script-lib` is a Rust library that **emulates Bitcoin script by converting valid script-path spends to key-path spends**. Intended for use within a Trusted Execution Environment (TEE), the library validates unlocking conditions and then authorizes the transaction using a deterministically derived private key.

This approach enables confidential execution of complex script, including opcodes not yet supported by the Bitcoin protocol. The actual on-chain footprint is a minimal key-path spend, preserving privacy and efficiency.

## Overview

The library operates on a two-step process: emulation and signing.

1.  **Emulation**: A transaction is constructed using an input spending a *real* `previous_outpoint` with a witness that is a script-path spend from an *emulated* P2TR `script_pubkey`. The library validates this emulated witness using a `Verifier`, which matches the API of `rust-bitcoinkernel`. If compiled with the `bitcoinkernel` feature, users can use the actual kernel as the default verifier, or they can provide an alternative verifier that enforces a different set of rules (ex: a fork of `bitcoinkernel` that supports Simplicity).

2.  **Signing**: If the transaction is valid, the library uses the provided parent private key and the merkle root of the *emulated* script path spend to derive a child private key, which corresponds to the internal public key of the *actual* UTXO being spent. The library then updates the transaction with a key-path spend signed with this child key.

To facilitate offline generation of the real `script_pubkey`, the child key is derived from the parent key using a non-hardened HMAC-SHA512 derivation scheme. This lets users generate addresses using the parent _public_ key, while the parent private key is secured elsewhere.

This library is intended to be run within a TEE, which is securely provisioned with the parent private key. This decouples script execution from on-chain settlement, keeping execution private and enabling new functionality with minimal trust assumptions.

## Failsafe Mechanism: Backup Script Path

To prevent funds from being irrecoverably locked if the TEE becomes unavailable, the library allows for the inclusion of an optional `backup_merkle_root` when creating the actual on-chain address. This backup merkle root defines the alternative spending paths that are available independently of the TEE.

A common use case for this feature is to include a timelocked recovery script (e.g., using `OP_CHECKSEQUENCEVERIFY`). If the primary TEE-based execution path becomes unavailable for any reason, the owner can wait for the timelock to expire and then recover the funds using a pre-defined backup script. This provides a crucial failsafe, ensuring that users retain ultimate control over their assets.

## Extensibility for Proposed Soft Forks

This library can be used to emulate proposed upgrades, such as new opcodes like `OP_CAT` or `OP_CTV` or new scripting languages like Simplicity. It accepts any verifier that adheres to the `rust-bitcoinkernel` API, allowing developers to experiment with new functionality by forking the kernel, without waiting for a soft fork to gain adoption on mainnet.

## Recommended Setup

This library is intended to be used within a Nitro Enclave, integrated with KMS such that any AWS account can provision an identical enclave with the same master private key. For maximum security, the KMS key should be created with a policy making it non-deletable and only accessible to enclaves running a specific image. The policy should also be irrevocable, ensuring the key cannot be used outside the enclave in the future.

To generate the master secret, an enclave should generate a random secret and use `GenerateDataKey` to encrypt it using KMS. To provision a different enclave with the secret, the user should provide the enclave the encrypted encryption key and the encrypted secret. The enclave can then decrypt the encryption key with KMS using `Decrypt` and subequently decrypt the secret.

Finally, the enclave should be able to expose the master public key, so that users can independently derive the on-chain address they should send funds to.

## Usage

### Verifier

```rust
/// Trait to abstract the behavior of the bitcoin script verifier, allowing
/// users to provide their own verifier.
pub trait Verifier {
    /// Verify a bitcoin script, mirroring the API of `bitcoinkernel::verify`.
    ///
    /// # Arguments
    /// * `script_pubkey` - The script public key to verify.
    /// * `amount` - The amount of the input being spent.
    /// * `tx_to` - The transaction containing the script.
    /// * `input_index` - The index of the input to verify.
    /// * `flags` - Script verification flags.
    /// * `spent_outputs` - The outputs being spent by the transaction.
    ///
    /// # Errors
    /// Returns `KernelError` if verification fails.
    fn verify(
        &self,
        script_pubkey: &[u8],
        amount: Option<i64>,
        tx_to: &[u8],
        input_index: u32,
        flags: Option<u32>,
        spent_outputs: &[TxOut],
    ) -> Result<(), Error>;
}

/// The default `Verifier` implementation that uses `bitcoinkernel`.
pub struct DefaultVerifier;
```

### Convert emulated transaction

```rust
/// Verifies an emulated Bitcoin script and signs the corresponding transaction.
///
/// This function performs script verification using bitcoinkernel, verifying an
/// emulated P2TR input. If successful, it derives an XOnlyPublicKey from the
/// parent key and the emulated merkle root, which is then tweaked with an optional
/// backup merkle root to derive the actual spent UTXO, which is then key path signed
/// with `SIGHASH_DEFAULT`.
///
/// # Arguments
/// * `verifier` - The verifier to use for script validation
/// * `emulated_script_pubkey` - The P2TR script to verify against
/// * `amount` - The amount for the input
/// * `emulated_tx_to` - Serialized transaction to verify and sign
/// * `input_index` - Index of the input to verify and sign (0-based)
/// * `emulated_spent_outputs` - Outputs being spent in the emulated transaction
/// * `actual_spent_outputs` - Actual outputs for signature generation
/// * `aux_rand` - Auxiliary random data for signing
/// * `parent_key` - Parent secret key used to derive child key for signing
/// * `backup_merkle_root` - Optional merkle root for backup script path spending
///
/// # Errors
/// Returns error if verification fails, key derivation fails, or signing fails
pub fn verify_and_sign<V: Verifier>(
    verifier: &V,
    emulated_script_pubkey: &[u8],
    amount: i64,
    emulated_tx_to: &[u8],
    input_index: u32,
    emulated_spent_outputs: &[TxOut],
    actual_spent_outputs: &[TxOut],
    aux_rand: &[u8; 32],
    parent_key: SecretKey,
    backup_merkle_root: Option<TapNodeHash>,
) -> Result<Transaction, Error>;
```

### Generate an address

```rust
/// Generates P2TR address from a parent public key and the emulated merkle root,
/// with an optional backup merkle root.
///
/// # Arguments
/// * `parent_key` - The parent public key
/// * `emulated_merkle_root` - The merkle root of the emulated input
/// * `backup_merkle_root` - Optional merkle root for backup script path spending
/// * `network` - The network to generate the address for
///
/// # Errors
/// Returns an error if key derivation fails
fn generate_address(
    parent_key: PublicKey,
    emulated_merkle_root: TapNodeHash,
    backup_merkle_root: Option<TapNodeHash>,
    network: Network,
) -> Result<Address, secp256k1::Error>;
```

## Testing
The default `Verifier` implementation is based on `bitcoinkernel`, which is an optional feature but required to run the included tests.

Use the following command to run the test suite:

```bash
cargo test --features bitcoinkernel
```

Or run:

```bash
cargo test --all-features
```

## License

This project is licensed under the CC0-1.0 License.

## Author

Joshua Doman <joshsdoman@gmail.com>
