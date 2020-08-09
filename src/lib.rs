use wasm_bindgen::prelude::*;
use threshold_crypto::{Ciphertext, poly::Poly, PublicKey, SecretKey, serde_impl::SerdeSecret, SecretKeySet, Signature};

static mut SK_BYTES: [u8; 32] = [0; 32];
static mut PK_BYTES: [u8; 48] = [0; 48];
static mut SIG_BYTES: [u8; 96] = [0; 96];
static mut MSG_BYTES: [u8; 1049600] = [0; 1049600]; // 1 MiB + 1 KiB
static mut CT_BYTES: [u8; 1049600] = [0; 1049600]; // 1 MiB + 1 KiB
// rng.next() is called 4 times during encrypt
// rng.next() is called up to 48 times during Poly::random(10, rng)
// so use these values instead of trying to use OsRng. Since javascript can
// only set u32 use 2 of these for every call to rng.next()
static mut RNG_VALUES: [u32; 200] = [0; 200];
static mut RNG_INDEX: usize = 0;
static mut RNG_NEXT_COUNT: usize = 0;
// Poly which can be converted into SecretKeySet
// Threshold of 10 gives size of 360 bytes when serialized
static mut POLY_BYTES: [u8; 360] = [0; 360];
static mut MSK_BYTES: [u8; 32] = [0; 32];
static mut MPK_BYTES: [u8; 48] = [0; 48];
static mut SKSHARE_BYTES: [u8; 32] = [0; 32];
static mut PKSHARE_BYTES: [u8; 48] = [0; 48];

#[wasm_bindgen]
pub fn set_rng_value(i: usize, v: u32) {
    unsafe {
        RNG_VALUES[i] = v;
    }
}
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
pub fn set_poly_byte(i: usize, v: u8) {
    unsafe {
        POLY_BYTES[i] = v;
    }
}
#[wasm_bindgen]
pub fn get_poly_byte(i: usize) -> u8 {
    unsafe {
        POLY_BYTES[i]
    }
}
#[wasm_bindgen]
pub fn set_msk_byte(i: usize, v: u8) {
    unsafe {
        MSK_BYTES[i] = v;
    }
}
#[wasm_bindgen]
pub fn get_msk_byte(i: usize) -> u8 {
    unsafe {
        MSK_BYTES[i]
    }
}
#[wasm_bindgen]
pub fn set_mpk_byte(i: usize, v: u8) {
    unsafe {
        MPK_BYTES[i] = v;
    }
}
#[wasm_bindgen]
pub fn get_mpk_byte(i: usize) -> u8 {
    unsafe {
        MPK_BYTES[i]
    }
}
#[wasm_bindgen]
pub fn set_skshare_byte(i: usize, v: u8) {
    unsafe {
        SKSHARE_BYTES[i] = v;
    }
}
#[wasm_bindgen]
pub fn get_skshare_byte(i: usize) -> u8 {
    unsafe {
        SKSHARE_BYTES[i]
    }
}
#[wasm_bindgen]
pub fn set_pkshare_byte(i: usize, v: u8) {
    unsafe {
        PKSHARE_BYTES[i] = v;
    }
}
#[wasm_bindgen]
pub fn get_pkshare_byte(i: usize) -> u8 {
    unsafe {
        PKSHARE_BYTES[i]
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
pub fn encrypt(msg_size: usize, seed1: u64, seed2: u64) -> usize {
    unsafe {
        // create public key vec from input parameters
        let pk = PublicKey::from_bytes(PK_BYTES).unwrap();
        // create msg vec from input parameters
        let mut msg = Vec::new();
        for i in 0..msg_size {
            msg.push(MSG_BYTES[i]);
        }
        let seed: u64 = seed1 << 32 + seed2;
        let mut rng = CountingRng(seed);
        let ct = pk.encrypt_with_rng(&mut rng, msg);
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

//#[wasm_bindgen]
//pub fn derive_pmk_from_sks() {
//    unsafe {
//        let sks: SecretKeySet = bincode::deserialize(&POLY_BYTES).unwrap();
//        let pmk_vec = sks.public_keys().public_key().to_bytes().to_vec();
//        for i in 0..pmk_vec.len() {
//            PMK_BYTES[i] = pmk_vec[i];
//        }
//    }
//}

#[wasm_bindgen]
pub fn generate_poly(threshold: usize, seed1: u64, seed2: u64) -> usize {
    unsafe {
        let seed: u64 = seed1 << 32 + seed2;
        let mut rng = CountingRng(seed);
        let poly = Poly::random(threshold, &mut rng);
        let poly_vec = bincode::serialize(&poly).unwrap();
        for i in 0..poly_vec.len() {
            POLY_BYTES[i] = poly_vec[i];
        }
        return poly_vec.len()
    }
}

#[wasm_bindgen]
pub fn get_poly_degree() -> usize {
    unsafe {
        let poly: Poly = bincode::deserialize(&POLY_BYTES).unwrap();
        poly.degree()
    }
}

#[wasm_bindgen]
pub fn derive_master_key() {
    unsafe {
        let poly: Poly = bincode::deserialize(&POLY_BYTES).unwrap();
        // see https://github.com/poanetwork/threshold_crypto/blob/7709462f2df487ada3bb3243060504b5881f2628/src/lib.rs#L685
        let mut fr = poly.evaluate(0);
        let msk = SecretKey::from_mut(&mut fr);
        let msk_vec = bincode::serialize(&SerdeSecret(&msk)).unwrap();
        for i in 0..msk_vec.len() {
            MSK_BYTES[i] = msk_vec[i];
        }
        //// public key
        // could also use let mpk = msk.public_key();
        let skset: SecretKeySet = SecretKeySet::from(poly);
        let pkset = skset.public_keys();
        let mpk = pkset.public_key();
        let mpk_vec = mpk.to_bytes().to_vec();
        for i in 0..mpk_vec.len() {
            MPK_BYTES[i] = mpk_vec[i];
        }
    }
}

#[wasm_bindgen]
pub fn derive_key_share(i: usize) {
    unsafe {
        let poly: Poly = bincode::deserialize(&POLY_BYTES).unwrap();
        // secret key
        let skset: SecretKeySet = SecretKeySet::from(poly);
        let skshare = skset.secret_key_share(i);
        let skshare_vec = bincode::serialize(&SerdeSecret(&skshare)).unwrap();
        for i in 0..skshare_vec.len() {
            SKSHARE_BYTES[i] = skshare_vec[i];
        }
        // public key
        let pkset = skset.public_keys();
        let pkshare = pkset.public_key_share(i);
        let pkshare_vec = pkshare.to_bytes().to_vec();
        for i in 0..pkshare_vec.len() {
            PKSHARE_BYTES[i] = pkshare_vec[i];
        }
    }
}

#[wasm_bindgen]
pub fn get_rng_next_count() -> usize {
    unsafe {
        RNG_NEXT_COUNT
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
        unsafe {
            let mut rng_value: u64 = 0;
            rng_value = rng_value + u64::from(RNG_VALUES[RNG_INDEX]);
            rng_value = rng_value << 32;
            rng_value = rng_value + u64::from(RNG_VALUES[RNG_INDEX+1]);
            self.0 = rng_value;
            RNG_INDEX = (RNG_INDEX + 2) % RNG_VALUES.len();
            RNG_NEXT_COUNT = RNG_NEXT_COUNT + 1;
            self.0
        }
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        Ok(self.fill_bytes(dest))
    }
}
