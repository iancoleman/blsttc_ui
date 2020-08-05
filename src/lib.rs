use wasm_bindgen::prelude::*;
use threshold_crypto::{Ciphertext, PublicKey, SecretKey, Signature};

static mut SK_BYTES: [u8; 32] = [0; 32];
static mut PK_BYTES: [u8; 48] = [0; 48];
static mut SIG_BYTES: [u8; 96] = [0; 96];
static mut MSG_BYTES: [u8; 1049600] = [0; 1049600]; // 1 MiB + 1 KiB
static mut CT_BYTES: [u8; 1049600] = [0; 1049600]; // 1 MiB + 1 KiB

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
pub fn set_ct_byte(i: usize, v: u8) {
    unsafe {
        CT_BYTES[i] = v;
    }
}
#[wasm_bindgen]
pub fn get_ct_byte(i: usize) -> u8 {
    unsafe {
        CT_BYTES[i]
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

#[wasm_bindgen]
pub fn encrypt(msg_size: usize) -> usize {
    unsafe {
        // create public key vec from input parameters
        let pk = PublicKey::from_bytes(PK_BYTES).unwrap();
        // create msg vec from input parameters
        let mut msg = Vec::new();
        for i in 0..msg_size {
            msg.push(MSG_BYTES[i]);
        }
        // TODO understand the use of encrypt_with_rng better and risk of using
        // dangerous_seed and dangerous_rng here
        let dangerous_seed = 32384702;
        let mut dangerous_rng = CountingRng(dangerous_seed);
        let ct = pk.encrypt_with_rng(&mut dangerous_rng, msg);
        let ct_vec = bincode::serialize(&ct).unwrap();
        for i in 0..ct_vec.len() {
            CT_BYTES[i] = ct_vec[i];
        }
        return ct_vec.len()
    }
}

#[wasm_bindgen]
pub fn decrypt(ct_size: usize) -> usize {
    unsafe {
        // create secret key vec from input parameters
        let sk: SecretKey = bincode::deserialize(&SK_BYTES).unwrap();
        // create ct vec from input parameters
        let mut ct_vec = Vec::new();
        for i in 0..ct_size {
            ct_vec.push(CT_BYTES[i]);
        }
        let ct: Ciphertext = bincode::deserialize(&ct_vec).unwrap();
        if !ct.verify() {
            return 0;
        }
        let msg = sk.decrypt(&ct).unwrap();
        for i in 0..msg.len() {
            MSG_BYTES[i] = msg[i];
        }
        return msg.len()
    }
}


// https://rust-random.github.io/rand/rand/trait.RngCore.html
use rand_core::{RngCore, Error, impls};

struct CountingRng(u64);

impl RngCore for CountingRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        Ok(self.fill_bytes(dest))
    }
}
