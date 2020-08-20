use wasm_bindgen::prelude::*;
use threshold_crypto::{Ciphertext, Fr, PublicKey, PublicKeySet, SecretKey, SecretKeySet, SecretKeyShare, Signature, poly::{
    Poly,
    BivarPoly,
    Commitment,
}, serde_impl::SerdeSecret, ff::Field};

// DKG constants
const MAX_NODES: usize = 10;
const MAX_ROW_SIZE: usize = 360;
const MAX_COMMITMENT_SIZE: usize = 536;
const MAX_SHARES: usize = MAX_NODES * MAX_NODES;
const ROW_BYTES: usize = MAX_ROW_SIZE * MAX_SHARES;
const BIVAR_COMMITMENTS_SIZE: usize = MAX_COMMITMENT_SIZE * MAX_NODES;

static mut SK_BYTES: [u8; 32] = [0; 32];
static mut PK_BYTES: [u8; 48] = [0; 48];
static mut SIG_BYTES: [u8; 96] = [0; 96];
static mut MSG_BYTES: [u8; 1049600] = [0; 1049600]; // 1 MiB + 1 KiB
static mut CT_BYTES: [u8; 1049600] = [0; 1049600]; // 1 MiB + 1 KiB
// rng.next() is called 4 times during encrypt
// rng.next() is called up to 48 times during Poly::random(10, rng)
// rng.next() is called up to 376 times during BivarPoly::random(10, rng)
// BivarPoly may be called up to MAX_NODES times in generate_bivars.
// Use these values instead of trying to use OsRng. Since javascript can
// only set u32 use 2 of these for every call to rng.next()
const RNG_VALUES_SIZE: usize = 376 * 2 * MAX_NODES;
static mut RNG_VALUES: [u32; RNG_VALUES_SIZE] = [0; RNG_VALUES_SIZE];
static mut RNG_INDEX: usize = 0;
static mut RNG_NEXT_COUNT: usize = 0;
// Poly which can be converted into SecretKeySet
// Threshold of 10 gives poly size of 360 bytes when serialized
// Threshold of 10 gives commitment size of 536 bytes when serialized
static mut POLY_BYTES: [u8; 360] = [0; 360];
static mut MSK_BYTES: [u8; 32] = [0; 32];
static mut MPK_BYTES: [u8; 48] = [0; 48];
static mut MC_BYTES: [u8; 536] = [0; 536];
static mut SKSHARE_BYTES: [u8; 32] = [0; 32];
static mut PKSHARE_BYTES: [u8; 48] = [0; 48];
// DKG variables
// Threshold of 10 gives row size of 360 bytes when serialized
// Threshold of 10 gives commitment size of 3184 bytes when serialized
static mut BIVAR_ROW_BYTES: [u8; ROW_BYTES] = [0; ROW_BYTES];
static mut BIVAR_COMMITMENTS_BYTES: [u8; BIVAR_COMMITMENTS_SIZE] = [0; BIVAR_COMMITMENTS_SIZE];
static mut BIVAR_SKS_BYTES: [u8; 32 * MAX_NODES] = [0; 32 * MAX_NODES];

#[wasm_bindgen]
pub fn get_rng_values_size() -> usize {
    RNG_VALUES_SIZE
}
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
pub fn set_mc_byte(i: usize, v: u8) {
    unsafe {
        MC_BYTES[i] = v;
    }
}
#[wasm_bindgen]
pub fn get_mc_byte(i: usize) -> u8 {
    unsafe {
        MC_BYTES[i]
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
pub fn set_bivar_row_byte(i: usize, from_node: usize, to_node: usize, v: u8) {
    unsafe {
        let share_index = from_node * MAX_NODES + to_node;
        let row_byte_start = share_index * MAX_ROW_SIZE;
        BIVAR_ROW_BYTES[row_byte_start + i] = v;
    }
}
#[wasm_bindgen]
pub fn get_bivar_row_byte(i: usize, from_node: usize, to_node: usize) -> u8 {
    unsafe {
        let share_index = from_node * MAX_NODES + to_node;
        let row_byte_start = share_index * MAX_ROW_SIZE;
        BIVAR_ROW_BYTES[row_byte_start + i]
    }
}
#[wasm_bindgen]
pub fn set_bivar_commitments_byte(i: usize, from_node: usize, v: u8) {
    unsafe {
        let commitment_byte_start = from_node * MAX_COMMITMENT_SIZE;
        BIVAR_COMMITMENTS_BYTES[commitment_byte_start + i] = v;
    }
}
#[wasm_bindgen]
pub fn get_bivar_commitments_byte(i: usize, from_node: usize) -> u8 {
    unsafe {
        let commitment_byte_start = from_node * MAX_COMMITMENT_SIZE;
        BIVAR_COMMITMENTS_BYTES[commitment_byte_start + i]
    }
}
#[wasm_bindgen]
pub fn set_bivar_sks_byte(i: usize, node_index: usize, v: u8) {
    unsafe {
        let sks_byte_start = 32 * node_index;
        BIVAR_SKS_BYTES[sks_byte_start + i] = v;
    }
}
#[wasm_bindgen]
pub fn get_bivar_sks_byte(i: usize, node_index: usize) -> u8 {
    unsafe {
        let sks_byte_start = 32 * node_index;
        BIVAR_SKS_BYTES[sks_byte_start + i]
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
        let mut rng = ExternalRng(0);
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

#[wasm_bindgen]
pub fn generate_poly(threshold: usize) -> usize {
    unsafe {
        let mut rng = ExternalRng(0);
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
        let commitment = poly.commitment();
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
        // master commitment
        let commitment_vec = bincode::serialize(&commitment).unwrap();
        for i in 0..commitment_vec.len() {
            set_mc_byte(i, commitment_vec[i]);
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

// fills BIVAR_ROW_BYTES and BIVAR_COMMITMENT_BYTES
// with the required number of rows and commitments,
// although not all are necessarily going to be used.
// Values are concatenated into the BYTES vectors.
#[wasm_bindgen]
pub fn generate_bivars(threshold: usize, total_nodes: usize) {
    unsafe {
        let mut rng = ExternalRng(0);
        // Initialize the group master public key (a commitment, ie
        // equivalent to a PublicKeySet which it is converted to at the end)
        let mut mpk_commitment = Poly::zero().commitment();
        // Initialize the group master secret key, which is never known to
        // any node but is shown for information.
        let mut msk = Poly::zero();
        // Initialize each node secret key share
        let mut secret_key_shares = Vec::new();
        for _ in 0..total_nodes {
            let sk_val = Fr::zero();
            secret_key_shares.push(sk_val);
        }
        // Each node will create part of the group master public key
        // and part of each other node secret key share.
        for from_node in 0..total_nodes {
            // The 'from' node creates a contribution which is a BivarPoly,
            // from which rows (secret key shares) and
            // the commitment (master public key part)
            // can be calculated.
            let bivar = BivarPoly::random(threshold, &mut rng);
            // Add this to the secret key set
            msk += bivar.row(0);
            // commitment (public part)
            // In BLS-DKG library the commitment itself is shared, but only
            // commitment.row(0) is used in calculation of the master
            // public key so we'll only store the commitment.row(0).
            let commitment = bivar.commitment();
            let commitment_vec = bincode::serialize(&commitment).unwrap();
            for i in 0..commitment_vec.len() {
                set_bivar_commitments_byte(i, from_node, commitment_vec[i]);
            }
            // update the group master public key with this commitment data
            mpk_commitment += commitment.row(0);
            // Calculate the secret key parts to be shared with other nodes
            for to_node in 0..total_nodes {
                // row (secret part)
                let row = bivar.row(to_node+1);
                // add this to the secret key share for the to node
                secret_key_shares[to_node].add_assign(&row.evaluate(0));
                // record the row
                let row_vec = bincode::serialize(&row).unwrap();
                for i in 0..row_vec.len() {
                    set_bivar_row_byte(i, from_node, to_node, row_vec[i]);
                }
            }
        }
        // save the master commitment
        let mpk_commitment_vec = bincode::serialize(&mpk_commitment).unwrap();
        for i in 0..mpk_commitment_vec.len() {
            set_mc_byte(i, mpk_commitment_vec[i]);
        }
        // save the group master public key
        let mpkset = PublicKeySet::from(mpk_commitment);
        let mpk = mpkset.public_key();
        let mpk_vec = mpk.to_bytes().to_vec();
        for i in 0..mpk_vec.len() {
            MPK_BYTES[i] = mpk_vec[i];
        }
        // save the master secret key
        let msk_vec = bincode::serialize(&msk).unwrap();
        for i in 0..msk_vec.len() {
            POLY_BYTES[i] = msk_vec[i];
        }
        // save the secret key shares
        for node_index in 0..total_nodes {
            let mut sk_val = secret_key_shares[node_index];
            let sk = SecretKeyShare::from_mut(&mut sk_val);
            let sk_vec = bincode::serialize(&SerdeSecret(&sk)).unwrap();
            for i in 0..sk_vec.len() {
                set_bivar_sks_byte(i, node_index, sk_vec[i]);
            }
        }
    }
}


// https://rust-random.github.io/rand/rand/trait.RngCore.html
use rand_core::{RngCore, Error, impls};

struct ExternalRng(u64);

impl RngCore for ExternalRng {
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
