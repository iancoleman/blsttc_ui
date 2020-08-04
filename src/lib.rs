use wasm_bindgen::prelude::*;
use threshold_crypto::{PublicKey, SecretKey, Signature};

static mut SK_BYTES: [u8; 32] = [0; 32];
static mut PK_BYTES: [u8; 48] = [0; 48];
static mut SIG_BYTES: [u8; 96] = [0; 96];
static mut MSG_BYTES: [u8; 1049600] = [0; 1049600]; // 1 MiB + 1 KiB

#[wasm_bindgen]
pub fn set_sk_byte(i: usize, v: u8) {
    unsafe {
        SK_BYTES[i] = v;
    }
}
#[wasm_bindgen]
pub fn get_sk_byte(i: usize) -> u8 {
    unsafe {
        SK_BYTES[i]
    }
}
#[wasm_bindgen]
pub fn set_pk_byte(i: usize, v: u8) {
    unsafe {
        PK_BYTES[i] = v;
    }
}
#[wasm_bindgen]
pub fn get_pk_byte(i: usize) -> u8 {
    unsafe {
        PK_BYTES[i]
    }
}
#[wasm_bindgen]
pub fn set_sig_byte(i: usize, v: u8) {
    unsafe {
        SIG_BYTES[i] = v;
    }
}
#[wasm_bindgen]
pub fn get_sig_byte(i: usize) -> u8 {
    unsafe {
        SIG_BYTES[i]
    }
}
#[wasm_bindgen]
pub fn set_msg_byte(i: usize, v: u8) {
    unsafe {
        MSG_BYTES[i] = v;
    }
}
#[wasm_bindgen]
pub fn get_msg_byte(i: usize) -> u8 {
    unsafe {
        MSG_BYTES[i]
    }
}

#[wasm_bindgen]
// Requires sk_bytes to be already set.
// Puts pk result into pk_bytes.
pub fn derive_pk_from_sk() {
    unsafe {
        let sk: SecretKey = bincode::deserialize(&SK_BYTES).unwrap();
        let pk_vec = sk.public_key().to_bytes().to_vec();
        for i in 0..pk_vec.len() {
            PK_BYTES[i] = pk_vec[i];
        }
    }
}

#[wasm_bindgen]
pub fn sign_msg(msg_size: usize) {
    unsafe {
        // create secret key vec from input parameters
        let sk: SecretKey = bincode::deserialize(&SK_BYTES).unwrap();
        // create msg vec from input parameters
        let mut msg = Vec::new();
        for i in 0..msg_size {
            msg.push(MSG_BYTES[i]);
        }
        let sig = sk.sign(msg);
        let sig_vec = sig.to_bytes().to_vec();
        for i in 0..sig_vec.len() {
            SIG_BYTES[i] = sig_vec[i];
        }
    }
}

#[wasm_bindgen]
pub fn verify(msg_size: usize) -> bool {
    unsafe {
        // create public key vec from input parameters
        let pk = PublicKey::from_bytes(PK_BYTES).unwrap();
        // create signature vec from input parameters
        let sig = Signature::from_bytes(SIG_BYTES).unwrap();
        // create msg vec from input parameters
        let mut msg = Vec::new();
        for i in 0..msg_size {
            msg.push(MSG_BYTES[i]);
        }
        return pk.verify(&sig, msg)
    }
}
