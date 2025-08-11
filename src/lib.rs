// Written in 2025 by Joshua Doman <joshsdoman@gmail.com>
// SPDX-License-Identifier: CC0-1.0

//! # Confidential Script Library
//!
//! Verify Bitcoin script execution and authorize an equivalent on-chain transaction using a deterministically derived private key.
//!
//! This approach allows for confidential execution of complex script, including opcodes not yet supported by the Bitcoin protocol. The actual on-chain footprint is a minimal key-path spend, preserving privacy and efficiency.

//! ## Overview
//!
//! The library operates on a two-step process: emulation and signing.
//!
//! 1.  **Emulation**: A transaction is constructed using an input spending a *real* `previous_outpoint` with a witness that is a script-path spend from an *emulated* P2TR `script_pubkey`. This library validates this emulated witness using a `Verifier`, which closely matches the API of `rust-bitcoinkernel`. Using the `bitcoinkernel` feature, users can use this default verifier, or they can provide an alternative verifier that enforces a different set of rules (ex: a fork of `bitcoinkernel` that supports Simplicity).
//!
//! 2.  **Signing**: If verified, the library uses the provided parent private key and the merkle root of the *emulated* script path spend to derive a child private key, which corresponds to the internal public key of the *actual* UTXO being spent. The library then updates the transaction with a key-path spend using this child key.
//!
//! To facilitate offline generation of the real `script_pubkey`, the child key is derived from the parent key using a non-hardened HMAC-SHA512 derivation scheme. This lets users generate addresses using the parent public key, while keeping the parent private key secure.
//!
//! This library is intended to be run within a TEE, which is securely provisioned with the parent private key. This decouples script execution from on-chain settlemnt, keeping execution private and enabling new functionality with minimal trust assumptions.
//!
//! ## Failsafe Mechanism: Backup Script Path
//!
//! To prevent funds from being irrecoverably locked if the TEE becomes unavailable, the library allows for the inclusion of an optional `backup_merkle_root` when creating the actual on-chain address. This backup root defines alternative spending paths that are independent of the TEE.
//!
//! A common use case for this feature is to include a timelocked recovery script (e.g., using `OP_CHECKSEQUENCEVERIFY`). If the primary TEE-based execution path becomes unavailable for any reason, the owner can wait for the timelock to expire and then recover the funds using a pre-defined backup script. This provides a crucial failsafe, ensuring that users retain ultimate control over their assets.
//!
//! ## Extensibility for Proposed Soft Forks
//!
//! This library can be used to emulate proposed upgrades, such as new opcodes like `OP_CAT` or `OP_CTV` or new scripting languages like Simplicity. It accepts any verifier that adheres to the `rust-bitcoinkernel` API, allowing developers to experiment with new functionality by forking the kernel, without waiting for a soft fork to gain adoption on mainnet.
//!

// Coding conventions
#![deny(unsafe_code)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]

#[cfg(not(any(feature = "std")))]
compile_error!("`std` must be enabled");

use bitcoin::{
    Address, Network, ScriptBuf, TapNodeHash, TapSighashType, TapTweakHash, Transaction, TxIn,
    TxOut, Witness, XOnlyPublicKey,
    consensus::deserialize,
    hashes::Hash,
    key::Secp256k1,
    secp256k1,
    secp256k1::{Keypair, Message, PublicKey, Scalar, SecretKey, constants::CURVE_ORDER},
    sighash::{Prevouts, SighashCache},
    taproot::{ControlBlock, Signature},
};
#[cfg(feature = "bitcoinkernel")]
use bitcoinkernel::{KernelError, verify};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use sha2::Sha512;
use std::fmt;

/// Comprehensive error type for verify_and_sign operations
#[derive(Debug)]
pub enum Error {
    /// Verification failed
    VerificationFailed(String),
    /// Wrapped secp256k1 errors from cryptographic operations
    Secp256k1(secp256k1::Error),
    /// Input script is not P2TR
    NotTaprootSpend,
    /// Input is not a script path spend (missing taproot control block)
    NotScriptPathSpend,
    /// Invalid control block format or size
    InvalidControlBlock,
    /// Invalid amount
    InvalidAmount(bitcoin_units::amount::OutOfRangeError),
    /// Deserialization failed
    DeserializationFailed(bitcoin::consensus::encode::Error),
    /// Unable to calculate sighash
    InvalidSighash,
    /// Mismatch between emulated and actual spent outputs count
    SpentOutputsMismatch,
    /// Input index out of bounds
    InputIndexOutOfBounds,
}

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
#[cfg(feature = "bitcoinkernel")]
pub struct DefaultVerifier;

#[cfg(feature = "bitcoinkernel")]
impl Verifier for DefaultVerifier {
    fn verify(
        &self,
        script_pubkey: &[u8],
        amount: Option<i64>,
        tx_to: &[u8],
        input_index: u32,
        flags: Option<u32>,
        spent_outputs: &[TxOut],
    ) -> Result<(), Error> {
        let mut outputs = Vec::new();
        for txout in spent_outputs {
            let amount = txout.value.to_signed()?.to_sat();
            let script = bitcoinkernel::ScriptPubkey::try_from(txout.script_pubkey.as_bytes())?;
            outputs.push(bitcoinkernel::TxOut::new(&script, amount));
        }

        verify(
            &bitcoinkernel::ScriptPubkey::try_from(script_pubkey)?,
            amount,
            &bitcoinkernel::Transaction::try_from(tx_to)?,
            input_index,
            flags,
            &outputs,
        )?;

        Ok(())
    }
}

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
#[allow(clippy::too_many_arguments)]
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
) -> Result<Transaction, Error> {
    // Must be taproot spend
    if !ScriptBuf::from(emulated_script_pubkey.to_vec()).is_p2tr() {
        return Err(Error::NotTaprootSpend);
    }

    // Must be able to deserialize transaction
    let mut tx: Transaction = deserialize(emulated_tx_to)?;

    // Emulate and actual spent outputs must match input count and have same values
    if tx.input.len() != emulated_spent_outputs.len()
        || tx.input.len() != actual_spent_outputs.len()
        || emulated_spent_outputs
            .iter()
            .zip(actual_spent_outputs.iter())
            .any(|(e, a)| e.value != a.value)
    {
        return Err(Error::SpentOutputsMismatch);
    }

    // Input index must be in bounds
    if input_index as usize >= tx.input.len() {
        return Err(Error::InputIndexOutOfBounds);
    }

    // Must be script path spend
    let input = tx.input[input_index as usize].clone();
    let (Some(control_block), Some(tapleaf)) = (
        input.witness.taproot_control_block(),
        input.witness.taproot_leaf_script(),
    ) else {
        return Err(Error::NotScriptPathSpend);
    };
    let Ok(control_block) = ControlBlock::decode(control_block) else {
        return Err(Error::NotScriptPathSpend);
    };

    // Must satisfy verifier
    verifier.verify(
        emulated_script_pubkey,
        Some(amount),
        emulated_tx_to,
        input_index,
        None,
        emulated_spent_outputs,
    )?;

    // Calculate merkle root
    let mut curr_hash = TapNodeHash::from_script(tapleaf.script, tapleaf.version);
    for elem in &control_block.merkle_branch {
        curr_hash = TapNodeHash::from_node_hashes(curr_hash, *elem);
    }
    let merkle_root = curr_hash.to_byte_array();

    // Get actual internal key and child key to be tweaked for signing
    let secp = Secp256k1::new();
    let child_key = derive_child_secret_key(parent_key, merkle_root)?;
    let (internal_key, parity) = child_key.public_key(&secp).x_only_public_key();
    let child_key_for_tweak = if parity == secp256k1::Parity::Odd {
        child_key.negate()
    } else {
        child_key
    };

    // Update input at this index
    tx.input[input_index as usize] = TxIn {
        previous_output: input.previous_output,
        script_sig: ScriptBuf::new(),
        sequence: input.sequence, // Keep the same sequence
        witness: Witness::new(),
    };

    // Create sighash for the input
    let mut sighash_cache = SighashCache::new(&tx);
    let sighash_bytes = sighash_cache
        .taproot_key_spend_signature_hash(
            input_index as usize,
            &Prevouts::All(actual_spent_outputs),
            TapSighashType::Default,
        )
        .map_err(|_| Error::InvalidSighash)?;
    let mut sighash = [0u8; 32];
    sighash.copy_from_slice(sighash_bytes.as_byte_array());

    // Calculate the taproot tweaked private key for keypath spending
    let tweak = TapTweakHash::from_key_and_tweak(internal_key, backup_merkle_root);
    let tweaked_secret_key = child_key_for_tweak.add_tweak(&tweak.to_scalar())?;
    let tweaked_keypair = Keypair::from_secret_key(&secp, &tweaked_secret_key);

    // Sign the sighash
    let message = Message::from_digest(sighash);
    let signature = secp.sign_schnorr_with_aux_rand(&message, &tweaked_keypair, aux_rand);

    // Create taproot signature (schnorr signature + sighash type)
    let tap_signature = Signature {
        signature,
        sighash_type: TapSighashType::Default,
    };

    // Create witness for keypath spend
    let mut witness = Witness::new();
    witness.push(tap_signature.to_vec());
    tx.input[input_index as usize].witness = witness;

    Ok(tx)
}

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
pub fn generate_address(
    parent_key: PublicKey,
    emulated_merkle_root: TapNodeHash,
    backup_merkle_root: Option<TapNodeHash>,
    network: Network,
) -> Result<Address, secp256k1::Error> {
    let secp = Secp256k1::new();
    let child_key = derive_child_public_key(parent_key, emulated_merkle_root.to_byte_array())?;
    let internal_key = XOnlyPublicKey::from(child_key);
    let address = Address::p2tr(&secp, internal_key, backup_merkle_root, network);

    Ok(address)
}

/// Derives a child secret key from a parent secret key and emulated merkle root
/// using HMAC-SHA512 based key derivation (non-hardened derivation).
fn derive_child_secret_key(
    parent_key: SecretKey,
    emulated_merkle_root: [u8; 32],
) -> Result<SecretKey, secp256k1::Error> {
    let secp = Secp256k1::new();

    // Derive parent public key from parent secret
    let parent_public = parent_key.public_key(&secp);

    // Create HMAC-SHA512 with parent public key and merkle root
    let mut mac = Hmac::<Sha512>::new_from_slice(&parent_public.serialize())
        .expect("PublicKey serialization should always be non-empty");
    mac.update(&emulated_merkle_root);
    let hmac_result = mac.finalize().into_bytes();

    // Use first 32 bytes for key material
    let mut key_material = [0u8; 32];
    key_material.copy_from_slice(&hmac_result[..32]);
    let scalar = reduce_mod_order(&key_material);

    // Add the key material to parent private key
    parent_key.add_tweak(&scalar)
}

/// Derives a child public key from a parent public key and emulated merkle root
/// This allows public key derivation without access to private keys.
fn derive_child_public_key(
    parent_public: PublicKey,
    emulated_merkle_root: [u8; 32],
) -> Result<PublicKey, secp256k1::Error> {
    let secp = Secp256k1::new();

    // Create HMAC-SHA512 with parent public key as key
    let mut mac = Hmac::<Sha512>::new_from_slice(&parent_public.serialize())
        .expect("PublicKey serialization should always be non-empty");
    mac.update(&emulated_merkle_root);
    let hmac_result = mac.finalize().into_bytes();

    // Use first 32 bytes as scalar for point multiplication
    let mut key_material = [0u8; 32];
    key_material.copy_from_slice(&hmac_result[..32]);
    let scalar = reduce_mod_order(&key_material);

    // Add scalar * G to parent public key
    parent_public.add_exp_tweak(&secp, &scalar)
}

/// Safely reduces a 32-byte array modulo the secp256k1 curve order
fn reduce_mod_order(bytes: &[u8; 32]) -> Scalar {
    // Keep trying to create a scalar until we get a valid one
    // In practice, this loop will almost always execute only once
    let mut attempt = *bytes;
    loop {
        match Scalar::from_be_bytes(attempt) {
            Ok(scalar) => return scalar,
            Err(_) => {
                // If the value is too large, subtract the curve order
                // This is equivalent to modular reduction
                attempt = subtract_curve_order(&attempt);
            }
        }
    }
}

/// Subtract the secp256k1 curve order from a 32-byte big-endian number
fn subtract_curve_order(bytes: &[u8; 32]) -> [u8; 32] {
    let value = BigUint::from_bytes_be(bytes);
    let order = BigUint::from_bytes_be(&CURVE_ORDER);
    let reduced = value % order;

    let mut result = [0u8; 32];
    let reduced_bytes = reduced.to_bytes_be();
    let offset = 32 - reduced_bytes.len();
    result[offset..].copy_from_slice(&reduced_bytes);
    result
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::VerificationFailed(e) => {
                write!(f, "Verification failed: {e}")
            }
            Error::Secp256k1(e) => {
                write!(f, "Secp256k1 cryptographic operation failed: {e}")
            }
            Error::NotTaprootSpend => {
                write!(f, "Input is not a taproot spend")
            }
            Error::NotScriptPathSpend => {
                write!(
                    f,
                    "Input is not a script path spend (missing taproot control block)"
                )
            }
            Error::InvalidAmount(e) => {
                write!(f, "Invalid amount: {e}")
            }
            Error::InvalidControlBlock => {
                write!(f, "Input has invalid control block")
            }
            Error::DeserializationFailed(e) => {
                write!(f, "Failed to deserialize: {e}")
            }
            Error::InvalidSighash => {
                write!(f, "Unable to calculate sighash for input")
            }
            Error::SpentOutputsMismatch => {
                write!(
                    f,
                    "Mismatch between number of emulated and actual spent outputs"
                )
            }
            Error::InputIndexOutOfBounds => {
                write!(f, "Input index out of bounds")
            }
        }
    }
}

#[cfg(feature = "bitcoinkernel")]
impl From<KernelError> for Error {
    fn from(error: KernelError) -> Self {
        Error::VerificationFailed(error.to_string())
    }
}

impl From<secp256k1::Error> for Error {
    fn from(error: secp256k1::Error) -> Self {
        Error::Secp256k1(error)
    }
}

impl From<bitcoin::consensus::encode::Error> for Error {
    fn from(error: bitcoin::consensus::encode::Error) -> Self {
        Error::DeserializationFailed(error)
    }
}

impl From<bitcoin_units::amount::OutOfRangeError> for Error {
    fn from(error: bitcoin_units::amount::OutOfRangeError) -> Self {
        Error::InvalidAmount(error)
    }
}

#[cfg(test)]
#[cfg(feature = "bitcoinkernel")]
mod kernel_tests {
    use super::*;
    use bitcoin::{
        Address, Amount, Network, OutPoint, Script, ScriptBuf, Transaction, TxIn, TxOut, Txid,
        Witness,
        consensus::encode::serialize,
        hashes::Hash,
        key::UntweakedPublicKey,
        taproot::{LeafVersion, TaprootBuilder},
    };

    fn create_test_transaction_single_input() -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100000),
                script_pubkey: ScriptBuf::new_op_return([]),
            }],
        }
    }

    fn create_test_transaction_multi_input() -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint::new(Txid::all_zeros(), 1),
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(100000),
                script_pubkey: ScriptBuf::new_op_return([]),
            }],
        }
    }

    #[test]
    fn test_not_taproot_input() {
        let result = verify_and_sign(
            &DefaultVerifier,
            ScriptBuf::new_op_return([]).as_bytes(),
            0,
            &[],
            0,
            &[],
            &[],
            &[1u8; 32],
            SecretKey::from_slice(&[1u8; 32]).unwrap(),
            None,
        );

        assert!(matches!(result, Err(Error::NotTaprootSpend)));
    }

    #[test]
    fn test_unable_to_deserialize_tx() {
        let secp = Secp256k1::new();
        let internal_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let internal_key = UntweakedPublicKey::from(internal_secret.public_key(&secp));
        let address = Address::p2tr(&secp, internal_key, None, Network::Bitcoin);

        let result = verify_and_sign(
            &DefaultVerifier,
            address.script_pubkey().as_bytes(),
            0,
            &[],
            0,
            &[],
            &[],
            &[1u8; 32],
            SecretKey::from_slice(&[1u8; 32]).unwrap(),
            None,
        );

        assert!(matches!(result, Err(Error::DeserializationFailed(_))));
    }

    #[test]
    fn test_spent_output_mismatch() {
        let secp = Secp256k1::new();
        let internal_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let internal_key = UntweakedPublicKey::from(internal_secret.public_key(&secp));
        let address = Address::p2tr(&secp, internal_key, None, Network::Bitcoin);

        let result = verify_and_sign(
            &DefaultVerifier,
            address.script_pubkey().as_bytes(),
            0,
            &serialize(&create_test_transaction_single_input()),
            0,
            &[],
            &[],
            &[1u8; 32],
            SecretKey::from_slice(&[1u8; 32]).unwrap(),
            None,
        );

        assert!(matches!(result, Err(Error::SpentOutputsMismatch)));

        let txout = TxOut {
            value: Amount::from_sat(100000),
            script_pubkey: ScriptBuf::new_op_return([]),
        };
        let result = verify_and_sign(
            &DefaultVerifier,
            address.script_pubkey().as_bytes(),
            0,
            &serialize(&create_test_transaction_single_input()),
            0,
            &[txout.clone()],
            &[],
            &[1u8; 32],
            SecretKey::from_slice(&[1u8; 32]).unwrap(),
            None,
        );

        assert!(matches!(result, Err(Error::SpentOutputsMismatch)));

        let result = verify_and_sign(
            &DefaultVerifier,
            address.script_pubkey().as_bytes(),
            0,
            &serialize(&create_test_transaction_single_input()),
            0,
            &[txout.clone(), txout.clone()],
            &[txout.clone(), txout.clone()],
            &[1u8; 32],
            SecretKey::from_slice(&[1u8; 32]).unwrap(),
            None,
        );

        assert!(matches!(result, Err(Error::SpentOutputsMismatch)));

        let result = verify_and_sign(
            &DefaultVerifier,
            address.script_pubkey().as_bytes(),
            0,
            &serialize(&create_test_transaction_single_input()),
            0,
            &[txout.clone()],
            &[TxOut {
                value: Amount::from_sat(200000),
                script_pubkey: ScriptBuf::new_op_return([]),
            }],
            &[1u8; 32],
            SecretKey::from_slice(&[1u8; 32]).unwrap(),
            None,
        );

        assert!(matches!(result, Err(Error::SpentOutputsMismatch)));
    }

    #[test]
    fn test_input_index_out_of_bounds() {
        let secp = Secp256k1::new();
        let internal_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let internal_key = UntweakedPublicKey::from(internal_secret.public_key(&secp));
        let address = Address::p2tr(&secp, internal_key, None, Network::Bitcoin);

        let txout = TxOut {
            value: Amount::from_sat(100000),
            script_pubkey: ScriptBuf::new_op_return([]),
        };
        let result = verify_and_sign(
            &DefaultVerifier,
            address.script_pubkey().as_bytes(),
            0,
            &serialize(&create_test_transaction_single_input()),
            1,
            &[txout.clone()],
            &[txout.clone()],
            &[1u8; 32],
            SecretKey::from_slice(&[1u8; 32]).unwrap(),
            None,
        );

        assert!(matches!(result, Err(Error::InputIndexOutOfBounds)));
    }

    #[test]
    fn test_verify_and_sign_single_input_single_leaf() {
        let secp = Secp256k1::new();

        // 1. Create a dummy internal key
        let internal_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let internal_key = UntweakedPublicKey::from(internal_secret.public_key(&secp));

        // 2. Create OP_TRUE script leaf
        let op_true_script = Script::builder()
            .push_opcode(bitcoin::opcodes::OP_TRUE)
            .into_script();

        // 3. Build the taproot tree with single OP_TRUE leaf
        let taproot_builder = TaprootBuilder::new()
            .add_leaf(0, op_true_script.clone())
            .unwrap();
        let taproot_spend_info = taproot_builder.finalize(&secp, internal_key).unwrap();

        // 4. Create the emulated P2TR outputs
        let emulated_address = Address::p2tr(
            &secp,
            internal_key,
            taproot_spend_info.merkle_root(),
            Network::Bitcoin,
        );
        let emulated_spent_outputs = [TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: emulated_address.script_pubkey(),
        }];

        // 5. Get the control block for our OP_TRUE leaf
        let control_block = taproot_spend_info
            .control_block(&(op_true_script.clone(), LeafVersion::TapScript))
            .unwrap();

        // 6. Create the witness stack for script path spending
        let mut witness = Witness::new();
        witness.push(op_true_script.as_bytes());
        witness.push(control_block.serialize());

        // 7. Create emulated transaction
        let mut emulated_tx = create_test_transaction_single_input();
        emulated_tx.input[0].witness = witness;

        // 8. Create actual child secret
        let aux_rand = [1u8; 32];
        let parent_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let child_secret = derive_child_secret_key(
            parent_secret,
            taproot_spend_info.merkle_root().unwrap().to_byte_array(),
        )
        .unwrap();

        // 9. Create actual P2TR outputs
        let actual_internal_key = XOnlyPublicKey::from(child_secret.public_key(&secp));
        let actual_address = Address::p2tr(&secp, actual_internal_key, None, Network::Bitcoin);
        let mut actual_spent_outputs = emulated_spent_outputs.clone();
        actual_spent_outputs[0].script_pubkey = actual_address.script_pubkey();

        // 10. Verify and sign actual transaction
        let actual_tx = verify_and_sign(
            &DefaultVerifier,
            emulated_address.script_pubkey().as_bytes(),
            100_000,
            &serialize(&emulated_tx),
            0,
            &emulated_spent_outputs,
            &actual_spent_outputs,
            &aux_rand,
            parent_secret,
            None,
        )
        .unwrap();

        let mut actual_outputs = Vec::new();
        for txout in actual_spent_outputs {
            let amount = txout.value.to_signed().unwrap().to_sat();
            let script =
                bitcoinkernel::ScriptPubkey::try_from(txout.script_pubkey.as_bytes()).unwrap();
            actual_outputs.push(bitcoinkernel::TxOut::new(&script, amount));
        }

        // 11. Verify the actual transaction was properly signed
        let verify_result = bitcoinkernel::verify(
            &bitcoinkernel::ScriptPubkey::try_from(actual_address.script_pubkey().as_bytes())
                .unwrap(),
            Some(100_000),
            &bitcoinkernel::Transaction::try_from(serialize(&actual_tx).as_slice()).unwrap(),
            0,
            None,
            &actual_outputs,
        );

        assert!(verify_result.is_ok());
        assert_eq!(actual_tx.input[0].witness.len(), 1)
    }

    #[test]
    fn test_verify_and_sign_single_input_multiple_leaves() {
        let secp = Secp256k1::new();

        // 1. Create a dummy internal key
        let internal_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let internal_key = UntweakedPublicKey::from(internal_secret.public_key(&secp));

        // 2. Create script leaves
        let op_true_script = Script::builder()
            .push_opcode(bitcoin::opcodes::OP_TRUE)
            .into_script();
        let op_false_script = Script::builder()
            .push_opcode(bitcoin::opcodes::OP_FALSE)
            .into_script();

        // 3. Build the taproot tree with two leaves
        let taproot_builder = TaprootBuilder::new()
            .add_leaf(1, op_true_script.clone())
            .unwrap()
            .add_leaf(1, op_false_script.clone())
            .unwrap();
        let taproot_spend_info = taproot_builder.finalize(&secp, internal_key).unwrap();

        // 4. Create the emulated P2TR outputs
        let emulated_address = Address::p2tr(
            &secp,
            internal_key,
            taproot_spend_info.merkle_root(),
            Network::Bitcoin,
        );
        let emulated_spent_outputs = [TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: emulated_address.script_pubkey(),
        }];

        // 5. Get the control block for our OP_TRUE leaf
        let control_block = taproot_spend_info
            .control_block(&(op_true_script.clone(), LeafVersion::TapScript))
            .unwrap();

        // 6. Create the witness stack for script path spending
        let mut witness = Witness::new();
        witness.push(op_true_script.as_bytes());
        witness.push(control_block.serialize());

        // 7. Create emulated transaction
        let mut emulated_tx = create_test_transaction_single_input();
        emulated_tx.input[0].witness = witness;

        // 8. Create actual child secret
        let aux_rand = [1u8; 32];
        let parent_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let child_secret = derive_child_secret_key(
            parent_secret,
            taproot_spend_info.merkle_root().unwrap().to_byte_array(),
        )
        .unwrap();

        // 9. Create actual P2TR outputs
        let actual_internal_key = XOnlyPublicKey::from(child_secret.public_key(&secp));
        let actual_address = Address::p2tr(&secp, actual_internal_key, None, Network::Bitcoin);
        let mut actual_spent_outputs = emulated_spent_outputs.clone();
        actual_spent_outputs[0].script_pubkey = actual_address.script_pubkey();

        // 10. Verify and sign actual transaction
        let actual_tx = verify_and_sign(
            &DefaultVerifier,
            emulated_address.script_pubkey().as_bytes(),
            100_000,
            &serialize(&emulated_tx),
            0,
            &emulated_spent_outputs,
            &actual_spent_outputs,
            &aux_rand,
            parent_secret,
            None,
        )
        .unwrap();

        let mut actual_outputs = Vec::new();
        for txout in actual_spent_outputs {
            let amount = txout.value.to_signed().unwrap().to_sat();
            let script =
                bitcoinkernel::ScriptPubkey::try_from(txout.script_pubkey.as_bytes()).unwrap();
            actual_outputs.push(bitcoinkernel::TxOut::new(&script, amount));
        }

        // 11. Verify the actual transaction was properly signed
        let verify_result = bitcoinkernel::verify(
            &bitcoinkernel::ScriptPubkey::try_from(actual_address.script_pubkey().as_bytes())
                .unwrap(),
            Some(100_000),
            &bitcoinkernel::Transaction::try_from(serialize(&actual_tx).as_slice()).unwrap(),
            0,
            None,
            &actual_outputs,
        );

        assert!(verify_result.is_ok());
        assert_eq!(actual_tx.input[0].witness.len(), 1)
    }

    #[test]
    fn test_verify_and_sign_single_input_with_backup() {
        let secp = Secp256k1::new();

        // 1. Create a dummy internal key
        let internal_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let internal_key = UntweakedPublicKey::from(internal_secret.public_key(&secp));

        // 2. Create OP_TRUE script leaf
        let op_true_script = Script::builder()
            .push_opcode(bitcoin::opcodes::OP_TRUE)
            .into_script();

        // 3. Build the taproot tree with single OP_TRUE leaf
        let taproot_builder = TaprootBuilder::new()
            .add_leaf(0, op_true_script.clone())
            .unwrap();
        let taproot_spend_info = taproot_builder.finalize(&secp, internal_key).unwrap();

        // 4. Create the emulated P2TR outputs
        let emulated_address = Address::p2tr(
            &secp,
            internal_key,
            taproot_spend_info.merkle_root(),
            Network::Bitcoin,
        );
        let emulated_spent_outputs = [TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: emulated_address.script_pubkey(),
        }];

        // 5. Get the control block for our OP_TRUE leaf
        let control_block = taproot_spend_info
            .control_block(&(op_true_script.clone(), LeafVersion::TapScript))
            .unwrap();

        // 6. Create the witness stack for script path spending
        let mut witness = Witness::new();
        witness.push(op_true_script.as_bytes());
        witness.push(control_block.serialize());

        // 7. Create emulated transaction
        let mut emulated_tx = create_test_transaction_single_input();
        emulated_tx.input[0].witness = witness;

        // 8. Create actual child secret
        let aux_rand = [1u8; 32];
        let parent_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let child_secret = derive_child_secret_key(
            parent_secret,
            taproot_spend_info.merkle_root().unwrap().to_byte_array(),
        )
        .unwrap();

        // 9. Create actual P2TR outputs
        let actual_backup_merkle_root = taproot_spend_info.merkle_root();
        let actual_internal_key = XOnlyPublicKey::from(child_secret.public_key(&secp));
        let actual_address = Address::p2tr(
            &secp,
            actual_internal_key,
            actual_backup_merkle_root,
            Network::Bitcoin,
        );
        let mut actual_spent_outputs = emulated_spent_outputs.clone();
        actual_spent_outputs[0].script_pubkey = actual_address.script_pubkey();

        // 10. Verify and sign actual transaction
        let actual_tx = verify_and_sign(
            &DefaultVerifier,
            emulated_address.script_pubkey().as_bytes(),
            100_000,
            &serialize(&emulated_tx),
            0,
            &emulated_spent_outputs,
            &actual_spent_outputs,
            &aux_rand,
            parent_secret,
            actual_backup_merkle_root,
        )
        .unwrap();

        let mut actual_outputs = Vec::new();
        for txout in actual_spent_outputs {
            let amount = txout.value.to_signed().unwrap().to_sat();
            let script =
                bitcoinkernel::ScriptPubkey::try_from(txout.script_pubkey.as_bytes()).unwrap();
            actual_outputs.push(bitcoinkernel::TxOut::new(&script, amount));
        }

        // 11. Verify the actual transaction was properly signed
        let verify_result = bitcoinkernel::verify(
            &bitcoinkernel::ScriptPubkey::try_from(actual_address.script_pubkey().as_bytes())
                .unwrap(),
            Some(100_000),
            &bitcoinkernel::Transaction::try_from(serialize(&actual_tx).as_slice()).unwrap(),
            0,
            None,
            &actual_outputs,
        );

        assert!(verify_result.is_ok());
        assert_eq!(actual_tx.input[0].witness.len(), 1)
    }

    #[test]
    fn test_verify_and_sign_multi_input_tx() {
        let secp = Secp256k1::new();

        // 1. Create a dummy internal key
        let internal_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let internal_key = UntweakedPublicKey::from(internal_secret.public_key(&secp));

        // 2. Create OP_TRUE script leaf
        let op_true_script = Script::builder()
            .push_opcode(bitcoin::opcodes::OP_TRUE)
            .into_script();

        // 3. Build the taproot tree with single OP_TRUE leaf
        let taproot_builder = TaprootBuilder::new()
            .add_leaf(0, op_true_script.clone())
            .unwrap();
        let taproot_spend_info = taproot_builder.finalize(&secp, internal_key).unwrap();

        // 4. Create the emulated P2TR outputs
        let emulated_address = Address::p2tr(
            &secp,
            internal_key,
            taproot_spend_info.merkle_root(),
            Network::Bitcoin,
        );
        let emulated_spent_outputs = [
            TxOut {
                value: Amount::from_sat(200_000),
                script_pubkey: emulated_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: emulated_address.script_pubkey(),
            },
        ];

        // 5. Get the control block for our OP_TRUE leaf
        let control_block = taproot_spend_info
            .control_block(&(op_true_script.clone(), LeafVersion::TapScript))
            .unwrap();

        // 6. Create the witness stack for script path spending
        let mut witness = Witness::new();
        witness.push(op_true_script.as_bytes());
        witness.push(control_block.serialize());

        // 7. Create emulated transaction
        let mut emulated_tx = create_test_transaction_multi_input();
        emulated_tx.input[1].witness = witness;

        // 8. Create actual child secret
        let aux_rand = [1u8; 32];
        let parent_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let child_secret = derive_child_secret_key(
            parent_secret,
            taproot_spend_info.merkle_root().unwrap().to_byte_array(),
        )
        .unwrap();

        // 9. Create actual P2TR outputs
        let actual_internal_key = XOnlyPublicKey::from(child_secret.public_key(&secp));
        let actual_address = Address::p2tr(&secp, actual_internal_key, None, Network::Bitcoin);
        let mut actual_spent_outputs = emulated_spent_outputs.clone();
        actual_spent_outputs[1].script_pubkey = actual_address.script_pubkey();

        // 10. Verify and sign actual transaction
        let actual_tx = verify_and_sign(
            &DefaultVerifier,
            emulated_address.script_pubkey().as_bytes(),
            100_000,
            &serialize(&emulated_tx),
            1,
            &emulated_spent_outputs,
            &actual_spent_outputs,
            &aux_rand,
            parent_secret,
            None,
        )
        .unwrap();

        let mut actual_outputs = Vec::new();
        for txout in actual_spent_outputs {
            let amount = txout.value.to_signed().unwrap().to_sat();
            let script =
                bitcoinkernel::ScriptPubkey::try_from(txout.script_pubkey.as_bytes()).unwrap();
            actual_outputs.push(bitcoinkernel::TxOut::new(&script, amount));
        }

        // 11. Verify the actual transaction was properly signed
        let verify_result = bitcoinkernel::verify(
            &bitcoinkernel::ScriptPubkey::try_from(actual_address.script_pubkey().as_bytes())
                .unwrap(),
            Some(100_000),
            &bitcoinkernel::Transaction::try_from(serialize(&actual_tx).as_slice()).unwrap(),
            1,
            None,
            &actual_outputs,
        );

        assert!(verify_result.is_ok());
        assert_eq!(actual_tx.input[1].witness.len(), 1)
    }
}

#[cfg(test)]
mod non_kernel_tests {
    use super::*;
    use bitcoin::{
        Script,
        key::{Secp256k1, UntweakedPublicKey},
        taproot::TaprootBuilder,
    };

    #[test]
    fn test_generate_address() {
        let secp = Secp256k1::new();

        // 1. Create emulated script
        let emulated_script = Script::builder()
            .push_opcode(bitcoin::opcodes::OP_TRUE)
            .into_script();

        // 2. Build the taproot tree and create emulated merkle root
        let taproot_builder = TaprootBuilder::new()
            .add_leaf(0, emulated_script.clone())
            .unwrap();
        let dummy_internal_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let dummy_internal_key = UntweakedPublicKey::from(dummy_internal_secret.public_key(&secp));
        let taproot_spend_info = taproot_builder.finalize(&secp, dummy_internal_key).unwrap();
        let emulated_merkle_root = taproot_spend_info.merkle_root().unwrap();

        // 3. Create backup merkle root
        let backup_merkle_root = emulated_merkle_root;

        // 4. Generate an on-chain address
        let internal_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let master_public_key: PublicKey = internal_secret.public_key(&secp);
        let onchain_address = generate_address(
            master_public_key,
            emulated_merkle_root,
            Some(backup_merkle_root),
            Network::Bitcoin,
        );

        assert!(onchain_address.is_ok());
    }

    #[test]
    fn test_public_private_key_derivation_consistency() {
        let parent_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let parent_public = parent_secret.public_key(&Secp256k1::new());
        let merkle_root = [42u8; 32];

        let child_secret = derive_child_secret_key(parent_secret, merkle_root).unwrap();
        let child_public_from_secret = child_secret.public_key(&Secp256k1::new());
        let child_public_direct = derive_child_public_key(parent_public, merkle_root).unwrap();

        assert_eq!(child_public_from_secret, child_public_direct);
    }

    #[test]
    fn test_curve_order_reduction() {
        let max_bytes = [0xFF; 32];
        let reduced = reduce_mod_order(&max_bytes);
        // Should not panic and should be valid scalar
        #[allow(clippy::useless_conversion)]
        let _ = Scalar::from(reduced);
    }
}
