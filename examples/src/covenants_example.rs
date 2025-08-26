use bitcoin::{
    secp256k1::{self, PublicKey, SecretKey},
    TapNodeHash, Transaction, TxOut,
};
use bitcoinkernel_covenants::verify;
use confidential_script_lib::{generate_address, verify_and_sign, Error, Verifier};
use std::io::{Read, Write};
use vsock::{VsockListener, VsockStream, VMADDR_CID_ANY};

use serde::{Deserialize, Serialize};
use serde_json;

const ENCLAVE_PORT: u32 = 5005;

/// A custom `Verifier` implementation that uses `bitcoinkernel-covenants`.
pub struct CovenantVerifier;

impl Verifier for CovenantVerifier {
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
            let script =
                bitcoinkernel_covenants::ScriptPubkey::try_from(txout.script_pubkey.as_bytes())
                    .unwrap();
            outputs.push(bitcoinkernel_covenants::TxOut::new(&script, amount));
        }

        verify(
            &bitcoinkernel_covenants::ScriptPubkey::try_from(script_pubkey).unwrap(),
            amount,
            &bitcoinkernel_covenants::Transaction::try_from(tx_to).map_err(LocalKernelError)?,
            input_index,
            flags,
            &outputs,
        )
        .map_err(LocalKernelError)?;

        Ok(())
    }
}

pub struct LocalKernelError(pub bitcoinkernel_covenants::KernelError);
impl From<LocalKernelError> for confidential_script_lib::Error {
    fn from(e: LocalKernelError) -> Self {
        confidential_script_lib::Error::VerificationFailed(e.0.to_string())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum EnclaveRequest {
    CreateContractAddress {
        emulated_merkle_root: TapNodeHash,
        backup_merkle_root: Option<TapNodeHash>,
    },
    VerifyAndSign {
        emulated_tx_to: Vec<u8>,
        actual_prevouts: Vec<TxOut>,
        input_index: u32,
        aux_rand: [u8; 32],
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum SuccessResponse {
    ContractAddress { address: String },
    SignedTransaction(Transaction),
}

type EnclaveResponse = Result<SuccessResponse, String>;
fn main() {
    println!("Enclave server starting...");

    let port = vsock::VsockAddr::new(VMADDR_CID_ANY, ENCLAVE_PORT);
    let listener = VsockListener::bind(&port).expect("Failed to bind to VSock port");
    println!("Listening on port {}", ENCLAVE_PORT);

    // This is a hardcoded secret key for demonstration purposes only
    let enclave_secret = SecretKey::from_slice(&[0x01; 32]).expect("32 bytes, within curve order");

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                println!("Host connected. Handling request...");
                if let Err(e) = handle_connection(&mut stream, enclave_secret) {
                    eprintln!("Error handling connection: {}", e);

                    let response: EnclaveResponse = Err(format!("Enclave processing error: {}", e));
                    let response_bytes = serde_json::to_vec(&response).unwrap_or_default();
                    let _ = stream.write_all(&response_bytes);
                }
            }
            Err(e) => {
                eprintln!("connection failed: {}", e);
            }
        }
    }
}

pub fn process_request(request: EnclaveRequest, enclave_secret: SecretKey) -> EnclaveResponse {
    let secp = secp256k1::Secp256k1::new();
    let master_public_key: PublicKey = enclave_secret.public_key(&secp);

    println!("Enclave public key: {}", master_public_key);

    match request {
        EnclaveRequest::CreateContractAddress {
            emulated_merkle_root,
            backup_merkle_root,
        } => generate_address(
            master_public_key,
            emulated_merkle_root,
            backup_merkle_root,
            bitcoin::Network::Bitcoin,
        )
        .map_err(|e| e.to_string())
        .and_then(|address| {
            Ok(SuccessResponse::ContractAddress {
                address: address.to_string(),
            })
        }),
        EnclaveRequest::VerifyAndSign {
            emulated_tx_to,
            actual_prevouts,
            input_index,
            aux_rand,
        } => verify_and_sign(
            &CovenantVerifier,
            input_index,
            &emulated_tx_to,
            &actual_prevouts,
            &aux_rand,
            enclave_secret,
            None,
        )
        .map(SuccessResponse::SignedTransaction)
        .map_err(|e| e.to_string()),
    }
}

fn process_request_bytes(bytes: &[u8], enclave_secret: SecretKey) -> EnclaveResponse {
    let req: EnclaveRequest =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid request json: {e}"))?;
    process_request(req, enclave_secret)
}

fn handle_connection(stream: &mut VsockStream, enclave_secret: SecretKey) -> Result<(), Error> {
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).unwrap();

    let response: EnclaveResponse = process_request_bytes(&buffer, enclave_secret);

    let response_bytes = serde_json::to_vec(&response).unwrap();
    stream.write_all(&response_bytes).unwrap();
    stream.shutdown(std::net::Shutdown::Both).unwrap();

    println!("Request handled successfully.");
    Ok(())
}

#[cfg(test)]
mod enclave_tests {
    use bitcoin::{
        consensus::{encode::serialize, Encodable},
        hashes::{sha256, Hash},
        key::{Secp256k1, UntweakedPublicKey},
        opcodes::all::{OP_CAT, OP_EQUAL, OP_NOP4, OP_RETURN_204},
        secp256k1::{self, Message, PublicKey, SecretKey},
        taproot::{LeafVersion, TaprootBuilder},
        Address, Amount, Network, Opcode, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn,
        TxOut, Witness,
    };
    use confidential_script_lib::generate_address;

    const OP_CHECKTEMPLATEVERIFY: Opcode = OP_NOP4;
    const OP_CHECKSIGFROMSTACK: Opcode = OP_RETURN_204;

    use crate::{process_request, EnclaveRequest, SuccessResponse};

    fn create_test_tx_single_input() -> Transaction {
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
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::new_op_return([]),
            }],
        }
    }

    fn create_test_tx_wrong_output() -> Transaction {
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
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new_op_return([]),
            }],
        }
    }

    #[test]
    fn generate_address_test() {
        let secp = Secp256k1::new();
        let enclave_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let master_public_key: PublicKey = enclave_secret.public_key(&secp);

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

        let req = EnclaveRequest::CreateContractAddress {
            emulated_merkle_root,
            backup_merkle_root: Some(backup_merkle_root),
        };

        let res = process_request(req, enclave_secret);
        let contract_addr = match res {
            Ok(SuccessResponse::ContractAddress { address: a }) => a,
            other => panic!("unexpected response: {:?}", other),
        };

        let locally_created_addr = generate_address(
            master_public_key,
            emulated_merkle_root,
            Some(backup_merkle_root),
            Network::Bitcoin,
        )
        .expect("spend info");

        let parsed_unchecked = contract_addr
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .expect("address parseable");
        let parsed = parsed_unchecked
            .require_network(Network::Bitcoin)
            .expect("network check");
        assert_eq!(parsed, locally_created_addr);
    }

    #[test]
    fn test_verify_and_sign_op_cat() {
        let secp = Secp256k1::new();
        let enclave_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();

        // 1. Create a dummy internal key
        let internal_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let internal_key = UntweakedPublicKey::from(internal_secret.public_key(&secp));

        // 2. Create OP_CAT script leaf
        let op_cat_script = Script::builder()
            .push_opcode(OP_CAT)
            .push_slice(b"op_cat")
            .push_opcode(OP_EQUAL)
            .into_script();

        // 3. Build the taproot tree with single OP_CAT leaf
        let taproot_builder = TaprootBuilder::new()
            .add_leaf(0, op_cat_script.clone())
            .unwrap();
        let emulated_taproot_spend_info = taproot_builder.finalize(&secp, internal_key).unwrap();

        // 4. Get the control block for our OP_CAT leaf
        let control_block = emulated_taproot_spend_info
            .control_block(&(op_cat_script.clone(), LeafVersion::TapScript))
            .unwrap();

        // 5. Create the witness stack for script path spending
        let mut witness = Witness::new();
        witness.push(b"op_");
        witness.push(b"cat");
        witness.push(op_cat_script.as_bytes());
        witness.push(control_block.serialize());

        // 6. Create emulated transaction
        let mut emulated_tx = create_test_tx_single_input();

        emulated_tx.input[0].witness = witness;

        // 7. Create contract address in enclave
        let req = EnclaveRequest::CreateContractAddress {
            emulated_merkle_root: emulated_taproot_spend_info.merkle_root().unwrap(),
            backup_merkle_root: None,
        };

        let res = process_request(req, enclave_secret);
        let contract_addr = match res {
            Ok(SuccessResponse::ContractAddress { address: a }) => a,
            other => panic!("unexpected response: {:?}", other),
        };

        let parsed_unchecked = contract_addr
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .expect("address parseable");
        let actual_address = parsed_unchecked
            .require_network(Network::Bitcoin)
            .expect("network check");

        let aux_rand = [1u8; 32];

        let actual_prevouts = [TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: actual_address.script_pubkey(),
        }];

        // 8. Verify and sign actual transaction
        let req = EnclaveRequest::VerifyAndSign {
            emulated_tx_to: serialize(&emulated_tx),
            actual_prevouts: actual_prevouts.to_vec(),
            input_index: 0,
            aux_rand,
        };

        let res = process_request(req, enclave_secret);
        let signed = match res {
            Ok(SuccessResponse::SignedTransaction(tx)) => tx,
            other => panic!("unexpected response: {:?}", other),
        };

        let mut prevouts = Vec::new();
        for txout in actual_prevouts {
            let amount = txout.value.to_signed().unwrap().to_sat();
            let script =
                bitcoinkernel_covenants::ScriptPubkey::try_from(txout.script_pubkey.as_bytes())
                    .unwrap();
            prevouts.push(bitcoinkernel_covenants::TxOut::new(&script, amount));
        }

        let verify_result = bitcoinkernel_covenants::verify(
            &bitcoinkernel_covenants::ScriptPubkey::try_from(
                actual_address.script_pubkey().as_bytes(),
            )
            .unwrap(),
            Some(100_000),
            &bitcoinkernel_covenants::Transaction::try_from(serialize(&signed).as_slice()).unwrap(),
            0,
            None,
            &prevouts,
        );

        assert!(verify_result.is_ok(), "kernel verify failed");
        assert_eq!(signed.input[0].witness.len(), 1);
    }

    #[test]
    fn test_verify_and_sign_op_cat_fail() {
        let secp = Secp256k1::new();
        let enclave_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();

        // 1. Create a dummy internal key
        let internal_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let internal_key = UntweakedPublicKey::from(internal_secret.public_key(&secp));

        // 2. Create OP_CAT script leaf
        let op_cat_script = Script::builder()
            .push_opcode(OP_CAT)
            .push_slice(b"op_dog")
            .push_opcode(OP_EQUAL)
            .into_script();

        // 3. Build the taproot tree with single OP_CAT leaf
        let taproot_builder = TaprootBuilder::new()
            .add_leaf(0, op_cat_script.clone())
            .unwrap();
        let emulated_taproot_spend_info = taproot_builder.finalize(&secp, internal_key).unwrap();

        // 4. Get the control block for our OP_CAT leaf
        let control_block = emulated_taproot_spend_info
            .control_block(&(op_cat_script.clone(), LeafVersion::TapScript))
            .unwrap();

        // 5. Create the witness stack for script path spending (with wrong data to fail)
        let mut witness = Witness::new();
        witness.push(b"op_");
        witness.push(b"cat");
        witness.push(op_cat_script.as_bytes());
        witness.push(control_block.serialize());

        // 6. Create emulated transaction
        let mut emulated_tx = create_test_tx_single_input();
        emulated_tx.input[0].witness = witness;

        let script_pubkey = ScriptBuf::new_p2tr(
            &secp,
            internal_key,
            emulated_taproot_spend_info.merkle_root(),
        );
        println!("scriptPubKey: {}", hex::encode(script_pubkey.as_bytes()));
        println!("Emulated tx: {:?}", hex::encode(serialize(&emulated_tx)));

        // 7. Create contract address in enclave
        let req = EnclaveRequest::CreateContractAddress {
            emulated_merkle_root: emulated_taproot_spend_info.merkle_root().unwrap(),
            backup_merkle_root: None,
        };

        let res = process_request(req, enclave_secret);
        let contract_addr = match res {
            Ok(SuccessResponse::ContractAddress { address: a }) => a,
            other => panic!("unexpected response: {:?}", other),
        };

        let parsed_unchecked = contract_addr
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .expect("address parseable");
        let actual_address = parsed_unchecked
            .require_network(Network::Bitcoin)
            .expect("network check");

        let aux_rand = [1u8; 32];

        let actual_prevouts = [TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: actual_address.script_pubkey(),
        }];

        // 8. Verify and sign actual transaction
        let req = EnclaveRequest::VerifyAndSign {
            emulated_tx_to: serialize(&emulated_tx),
            actual_prevouts: actual_prevouts.to_vec(),
            input_index: 0,
            aux_rand,
        };

        let res = process_request(req, enclave_secret);

        assert!(res.is_err(), "kernel verify passed unexpectedly");
    }

    #[test]
    fn test_verify_and_sign_op_ctv_csfs() {
        let secp = Secp256k1::new();
        let enclave_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();

        // 1. Create a dummy internal key
        let internal_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let internal_key = UntweakedPublicKey::from(internal_secret.public_key(&secp));

        //calculate ctv hash
        let ctv_hash = ctv_hash(&create_test_tx_single_input().output, None, None);

        // 2. Create OP_CTV+CSFS script leaf
        let op_ctv_script = Script::builder()
            .push_slice(ctv_hash)
            .push_opcode(OP_CHECKTEMPLATEVERIFY)
            .push_x_only_key(&internal_key)
            .push_opcode(OP_CHECKSIGFROMSTACK)
            .into_script();

        // 3. Build the taproot tree with single OP_CTV+OP_CSFS leaf
        let taproot_builder = TaprootBuilder::new()
            .add_leaf(0, op_ctv_script.clone())
            .unwrap();
        let emulated_taproot_spend_info = taproot_builder.finalize(&secp, internal_key).unwrap();

        // 4. Get the control block for our OP_CTV+OP_CSFS  leaf
        let control_block = emulated_taproot_spend_info
            .control_block(&(op_ctv_script.clone(), LeafVersion::TapScript))
            .unwrap();

        let msg = Message::from_digest_slice(&ctv_hash).unwrap();
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &internal_secret);
        let signature: Vec<u8> = secp
            .sign_schnorr_no_aux_rand(&msg, &keypair)
            .as_ref()
            .to_vec();

        // 5. Create the witness stack for script path spending
        let mut witness = Witness::new();
        witness.push(signature);
        witness.push(op_ctv_script.as_bytes());
        witness.push(control_block.serialize());

        // 6. Create emulated transaction
        let mut emulated_tx = create_test_tx_single_input();
        emulated_tx.input[0].witness = witness;

        // 7. Create contract address in enclave
        let req = EnclaveRequest::CreateContractAddress {
            emulated_merkle_root: emulated_taproot_spend_info.merkle_root().unwrap(),
            backup_merkle_root: None,
        };

        let res = process_request(req, enclave_secret);
        let contract_addr = match res {
            Ok(SuccessResponse::ContractAddress { address: a }) => a,
            other => panic!("unexpected response: {:?}", other),
        };

        let parsed_unchecked = contract_addr
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .expect("address parseable");
        let actual_address = parsed_unchecked
            .require_network(Network::Bitcoin)
            .expect("network check");

        let aux_rand = [1u8; 32];

        let actual_prevouts = [TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: actual_address.script_pubkey(),
        }];

        // 8. Verify and sign actual transaction
        let req = EnclaveRequest::VerifyAndSign {
            emulated_tx_to: serialize(&emulated_tx),
            actual_prevouts: actual_prevouts.to_vec(),
            input_index: 0,
            aux_rand,
        };

        let res = process_request(req, enclave_secret);
        let signed = match res {
            Ok(SuccessResponse::SignedTransaction(tx)) => tx,
            other => panic!("unexpected response: {:?}", other),
        };

        let mut prevouts = Vec::new();
        for txout in actual_prevouts {
            let amount = txout.value.to_signed().unwrap().to_sat();
            let script =
                bitcoinkernel_covenants::ScriptPubkey::try_from(txout.script_pubkey.as_bytes())
                    .unwrap();
            prevouts.push(bitcoinkernel_covenants::TxOut::new(&script, amount));
        }

        let res = bitcoinkernel_covenants::verify(
            &bitcoinkernel_covenants::ScriptPubkey::try_from(
                actual_address.script_pubkey().as_bytes(),
            )
            .unwrap(),
            Some(100_000),
            &bitcoinkernel_covenants::Transaction::try_from(serialize(&signed).as_slice()).unwrap(),
            0,
            None,
            &prevouts,
        );

        assert!(res.is_ok(), "kernel verify failed");
        assert_eq!(signed.input[0].witness.len(), 1);
    }

    #[test]
    fn test_verify_and_sign_op_ctv_fail() {
        let secp = Secp256k1::new();
        let enclave_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();

        // 1. Create a dummy internal key
        let internal_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let internal_key = UntweakedPublicKey::from(internal_secret.public_key(&secp));

        //calculate ctv hash
        let ctv_hash = ctv_hash(&create_test_tx_single_input().output, None, None);

        // 2. Create OP_CTV script leaf
        let op_ctv_script = Script::builder()
            .push_slice(ctv_hash)
            .push_opcode(OP_CHECKTEMPLATEVERIFY)
            .into_script();

        // 3. Build the taproot tree with single OP_CTV+OP_CSFS leaf
        let taproot_builder = TaprootBuilder::new()
            .add_leaf(0, op_ctv_script.clone())
            .unwrap();
        let emulated_taproot_spend_info = taproot_builder.finalize(&secp, internal_key).unwrap();

        // 4. Get the control block for our OP_CTV+OP_CSFS  leaf
        let control_block = emulated_taproot_spend_info
            .control_block(&(op_ctv_script.clone(), LeafVersion::TapScript))
            .unwrap();

        // 5. Create the witness stack for script path spending
        let mut witness = Witness::new();
        witness.push(op_ctv_script.as_bytes());
        witness.push(control_block.serialize());

        // 6. Create the wrong emulated transaction
        let mut emulated_tx = create_test_tx_wrong_output();
        emulated_tx.input[0].witness = witness;

        // 7. Create contract address in enclave
        let req = EnclaveRequest::CreateContractAddress {
            emulated_merkle_root: emulated_taproot_spend_info.merkle_root().unwrap(),
            backup_merkle_root: None,
        };

        let res = process_request(req, enclave_secret);
        let contract_addr = match res {
            Ok(SuccessResponse::ContractAddress { address: a }) => a,
            other => panic!("unexpected response: {:?}", other),
        };

        let parsed_unchecked = contract_addr
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .expect("address parseable");
        let actual_address = parsed_unchecked
            .require_network(Network::Bitcoin)
            .expect("network check");

        let aux_rand = [1u8; 32];

        let actual_prevouts = [TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: actual_address.script_pubkey(),
        }];

        // 8. Verify and sign actual transaction
        let req = EnclaveRequest::VerifyAndSign {
            emulated_tx_to: serialize(&emulated_tx),
            actual_prevouts: actual_prevouts.to_vec(),
            input_index: 0,
            aux_rand,
        };

        let res = process_request(req, enclave_secret);

        assert!(res.is_err(), "kernel verify passed unexpectedly");
    }

    #[test]
    fn test_verify_and_sign_op_csfs_fail() {
        let secp = Secp256k1::new();
        let enclave_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();

        // 1. Create a dummy internal key
        let internal_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let internal_key = UntweakedPublicKey::from(internal_secret.public_key(&secp));

        // 2. Create CSFS script leaf
        let op_ctv_script = Script::builder()
            .push_slice(&[1u8; 32])
            .push_x_only_key(&internal_key)
            .push_opcode(OP_CHECKSIGFROMSTACK)
            .into_script();

        // 3. Build the taproot tree with single OP_CSFS leaf
        let taproot_builder = TaprootBuilder::new()
            .add_leaf(0, op_ctv_script.clone())
            .unwrap();
        let emulated_taproot_spend_info = taproot_builder.finalize(&secp, internal_key).unwrap();

        // 4. Get the control block for our OP_CSFS  leaf
        let control_block = emulated_taproot_spend_info
            .control_block(&(op_ctv_script.clone(), LeafVersion::TapScript))
            .unwrap();

        // sign the wrong message to fail
        let msg = Message::from_digest_slice(&[0u8; 32]).unwrap();
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &internal_secret);
        let signature: Vec<u8> = secp
            .sign_schnorr_no_aux_rand(&msg, &keypair)
            .as_ref()
            .to_vec();

        // 5. Create the witness stack for script path spending
        let mut witness = Witness::new();
        witness.push(signature);
        witness.push(op_ctv_script.as_bytes());
        witness.push(control_block.serialize());

        // 6. Create the wrong emulated transaction
        let mut emulated_tx = create_test_tx_wrong_output();
        emulated_tx.input[0].witness = witness;

        // 7. Create contract address in enclave
        let req = EnclaveRequest::CreateContractAddress {
            emulated_merkle_root: emulated_taproot_spend_info.merkle_root().unwrap(),
            backup_merkle_root: None,
        };

        let res = process_request(req, enclave_secret);
        let contract_addr = match res {
            Ok(SuccessResponse::ContractAddress { address: a }) => a,
            other => panic!("unexpected response: {:?}", other),
        };

        let parsed_unchecked = contract_addr
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .expect("address parseable");
        let actual_address = parsed_unchecked
            .require_network(Network::Bitcoin)
            .expect("network check");

        let aux_rand = [1u8; 32];

        let actual_prevouts = [TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: actual_address.script_pubkey(),
        }];

        // 8. Verify and sign actual transaction
        let req = EnclaveRequest::VerifyAndSign {
            emulated_tx_to: serialize(&emulated_tx),
            actual_prevouts: actual_prevouts.to_vec(),
            input_index: 0,
            aux_rand,
        };

        let res = process_request(req, enclave_secret);

        assert!(res.is_err(), "kernel verify passed unexpectedly");
    }

    /// Computes the CTV (CheckTemplateVerify) hash for a transaction, used to ensure that the outputs of a transaction match a specific template.
    pub fn ctv_hash(
        outputs: &[TxOut],
        timeout: Option<u32>,
        maybe_txin: Option<&TxIn>,
    ) -> [u8; 32] {
        let mut buffer = Vec::new();
        buffer.extend(2_i32.to_le_bytes()); // version
        buffer.extend(0_i32.to_le_bytes()); // locktime

        if let Some(txin) = maybe_txin {
            let script_sigs_hash = sha256::Hash::hash(&txin.script_sig.to_bytes());
            buffer.extend(script_sigs_hash.to_byte_array()); //scriptSigs hash (if any non-null scriptSigs)
        }

        buffer.extend(1_u32.to_le_bytes()); // number of inputs

        let seq = if let Some(timeout_value) = timeout {
            sha256::Hash::hash(&Sequence(timeout_value).0.to_le_bytes())
        } else {
            sha256::Hash::hash(&Sequence::ENABLE_RBF_NO_LOCKTIME.0.to_le_bytes())
        };

        buffer.extend(seq.to_byte_array()); // sequences hash

        let outputs_len = outputs.len() as u32;
        buffer.extend(outputs_len.to_le_bytes()); // number of outputs

        let mut output_bytes: Vec<u8> = Vec::new();
        for o in outputs {
            o.consensus_encode(&mut output_bytes).unwrap();
        }
        buffer.extend(sha256::Hash::hash(&output_bytes).to_byte_array()); // outputs hash

        buffer.extend(0_u32.to_le_bytes()); // inputs index

        let hash = sha256::Hash::hash(&buffer);
        hash.to_byte_array()
    }
}
