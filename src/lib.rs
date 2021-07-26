use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;
use blsttc::{Ciphertext, DecryptionShare, Fr, PublicKey, PublicKeySet, SecretKey, SecretKeySet, SecretKeyShare, Signature, SignatureShare, poly::{
    Poly,
    BivarPoly,
    Commitment,
}, ff::Field};
use std::str;

const SK_SIZE: usize = 32;
const PK_SIZE: usize = 48;
const SIG_SIZE: usize = 96;

// DKG constants
const MAX_NODES: usize = 10;
const MAX_ROW_SIZE: usize = 360;
const MAX_COMMITMENT_SIZE: usize = PK_SIZE * MAX_NODES;
const MAX_POLY_SIZE: usize = SK_SIZE * MAX_NODES;
const MAX_SHARES: usize = MAX_NODES * MAX_NODES;
const ROW_BYTES: usize = MAX_ROW_SIZE * MAX_SHARES;
const BIVAR_POLY_SIZE: usize = SK_SIZE * MAX_NODES * (MAX_NODES + 1) / 2;
const BIVAR_COMMITMENT_SIZE: usize = PK_SIZE * MAX_NODES * (MAX_NODES + 1) / 2;
// MSG can be up to 1 MiB + 1 KiB
const MAX_MSG_SIZE: usize = 1049600;
// CT has overhead of 144 B so is 1 MiB + 144 B
const MAX_CT_SIZE: usize = MAX_MSG_SIZE + 144;

static mut SK_BYTES: [u8; SK_SIZE] = [0; SK_SIZE];
static mut PK_BYTES: [u8; PK_SIZE] = [0; PK_SIZE];
static mut SIG_BYTES: [u8; SIG_SIZE] = [0; SIG_SIZE];
static mut MSG_BYTES: [u8; MAX_MSG_SIZE] = [0; MAX_MSG_SIZE];
static mut CT_BYTES: [u8; MAX_CT_SIZE] = [0; MAX_CT_SIZE];
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
// Poly and commitment
static mut POLY_BYTES: [u8; MAX_POLY_SIZE] = [0; MAX_POLY_SIZE];
static mut MSK_BYTES: [u8; SK_SIZE] = [0; SK_SIZE];
static mut MPK_BYTES: [u8; PK_SIZE] = [0; PK_SIZE];
static mut MC_BYTES: [u8; MAX_COMMITMENT_SIZE] = [0; MAX_COMMITMENT_SIZE];
static mut SKSHARE_BYTES: [u8; SK_SIZE] = [0; SK_SIZE];
static mut PKSHARE_BYTES: [u8; PK_SIZE] = [0; PK_SIZE];
// DKG variables
static mut BIVAR_ROW_BYTES: [u8; ROW_BYTES] = [0; ROW_BYTES];
static mut BIVAR_COMMITMENT_BYTES: [u8; BIVAR_COMMITMENT_SIZE] = [0; BIVAR_COMMITMENT_SIZE];
static mut BIVAR_SKS_BYTES: [u8; BIVAR_POLY_SIZE] = [0; BIVAR_POLY_SIZE];
static mut BIVAR_PKS_BYTES: [u8; BIVAR_COMMITMENT_SIZE] = [0; BIVAR_COMMITMENT_SIZE];
// Group signing variables
static mut SIGNATURE_SHARE_BYTES: [u8; SIG_SIZE * MAX_NODES] = [0; SIG_SIZE * MAX_NODES];
static mut SHARE_INDEXES: [usize; MAX_NODES] = [0; MAX_NODES];
static mut DECRYPTION_SHARES_BYTES: [u8; PK_SIZE * MAX_NODES] = [0; PK_SIZE * MAX_NODES];

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
pub fn get_rng_next_count() -> usize {
    unsafe {
        RNG_NEXT_COUNT
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
        BIVAR_COMMITMENT_BYTES[commitment_byte_start + i] = v;
    }
}
#[wasm_bindgen]
pub fn get_bivar_commitments_byte(i: usize, from_node: usize) -> u8 {
    unsafe {
        let commitment_byte_start = from_node * MAX_COMMITMENT_SIZE;
        BIVAR_COMMITMENT_BYTES[commitment_byte_start + i]
    }
}
#[wasm_bindgen]
pub fn set_bivar_sks_byte(i: usize, node_index: usize, v: u8) {
    unsafe {
        let sks_byte_start = SK_SIZE * node_index;
        BIVAR_SKS_BYTES[sks_byte_start + i] = v;
    }
}
#[wasm_bindgen]
pub fn get_bivar_sks_byte(i: usize, node_index: usize) -> u8 {
    unsafe {
        let sks_byte_start = SK_SIZE * node_index;
        BIVAR_SKS_BYTES[sks_byte_start + i]
    }
}
#[wasm_bindgen]
pub fn set_bivar_pks_byte(i: usize, node_index: usize, v: u8) {
    unsafe {
        let pks_byte_start = PK_SIZE * node_index;
        BIVAR_PKS_BYTES[pks_byte_start + i] = v;
    }
}
#[wasm_bindgen]
pub fn get_bivar_pks_byte(i: usize, node_index: usize) -> u8 {
    unsafe {
        let pks_byte_start = PK_SIZE * node_index;
        BIVAR_PKS_BYTES[pks_byte_start + i]
    }
}
#[wasm_bindgen]
pub fn set_signature_share_byte(i: usize, sig_index: usize, v: u8) {
    unsafe {
        let sig_byte_start = SIG_SIZE * sig_index;
        SIGNATURE_SHARE_BYTES[sig_byte_start + i] = v;
    }
}
#[wasm_bindgen]
pub fn get_signature_share_byte(i: usize, sig_index: usize) -> u8 {
    unsafe {
        let sig_byte_start = SIG_SIZE * sig_index;
        SIGNATURE_SHARE_BYTES[sig_byte_start + i]
    }
}
#[wasm_bindgen]
pub fn set_share_indexes(i: usize, v: usize) {
    unsafe {
        SHARE_INDEXES[i] = v;
    }
}
#[wasm_bindgen]
pub fn get_share_indexes(i: usize) -> usize {
    unsafe {
        SHARE_INDEXES[i]
    }
}
#[wasm_bindgen]
pub fn set_decryption_shares_byte(i: usize, share_index: usize, v: u8) {
    unsafe {
        let ds_byte_start = PK_SIZE * share_index;
        DECRYPTION_SHARES_BYTES[ds_byte_start + i] = v;
    }
}
#[wasm_bindgen]
pub fn get_decryption_shares_byte(i: usize, share_index: usize) -> u8 {
    unsafe {
        let ds_byte_start = PK_SIZE * share_index;
        DECRYPTION_SHARES_BYTES[ds_byte_start + i]
    }
}

#[wasm_bindgen]
// Requires sk_bytes to be already set.
// Puts pk result into pk_bytes.
pub fn derive_pk_from_sk() {
    let mut sk_bytes = [0_u8; SK_SIZE];
    for i in 0..SK_SIZE {
        sk_bytes[i] = get_sk_byte(i);
    }
    let sk = SecretKey::from_bytes(sk_bytes).unwrap();
    let pk_vec = sk.public_key().to_bytes().to_vec();
    for i in 0..pk_vec.len() {
        set_pk_byte(i, pk_vec[i]);
    }
}

#[wasm_bindgen]
pub fn sign_msg(msg_size: usize) {
    // create secret key vec from input parameters
    let mut sk_bytes = [0_u8; SK_SIZE];
    for i in 0..SK_SIZE {
        sk_bytes[i] = get_sk_byte(i);
    }
    let sk = SecretKey::from_bytes(sk_bytes).unwrap();
    // create msg vec from input parameters
    let mut msg = Vec::new();
    for i in 0..msg_size {
        let msg_byte = get_msg_byte(i);
        msg.push(msg_byte);
    }
    let sig = sk.sign(msg);
    let sig_vec = sig.to_bytes().to_vec();
    for i in 0..sig_vec.len() {
        set_sig_byte(i, sig_vec[i]);
    }
}

#[wasm_bindgen]
pub fn verify(msg_size: usize) -> bool {
    // create public key vec from input parameters
    let mut pk_bytes: [u8; PK_SIZE] = [0; PK_SIZE];
    for i in 0..PK_SIZE {
        pk_bytes[i] = get_pk_byte(i);
    }
    let pk = PublicKey::from_bytes(pk_bytes).unwrap();
    // create signature vec from input parameters
    let mut sig_bytes: [u8; SIG_SIZE] = [0; SIG_SIZE];
    for i in 0..SIG_SIZE {
        sig_bytes[i] = get_sig_byte(i);
    }
    let sig = Signature::from_bytes(sig_bytes).unwrap();
    // create msg vec from input parameters
    let mut msg = Vec::new();
    for i in 0..msg_size {
        msg.push(get_msg_byte(i));
    }
    return pk.verify(&sig, msg)
}

#[wasm_bindgen]
pub fn encrypt(msg_size: usize) -> usize {
    // create public key vec from input parameters
    let mut pk_bytes: [u8; PK_SIZE] = [0; PK_SIZE];
    for i in 0..PK_SIZE {
        pk_bytes[i] = get_pk_byte(i);
    }
    let pk = PublicKey::from_bytes(pk_bytes).unwrap();
    // create msg vec from input parameters
    let mut msg = Vec::new();
    for i in 0..msg_size {
        msg.push(get_msg_byte(i));
    }
    let mut rng = ExternalRng(0);
    let ct = pk.encrypt_with_rng(&mut rng, msg);
    let ct_vec = ct.to_bytes();
    for i in 0..ct_vec.len() {
        set_ct_byte(i, ct_vec[i]);
    }
    return ct_vec.len()
}

#[wasm_bindgen]
pub fn decrypt(ct_size: usize) -> usize {
    // create secret key vec from input parameters
    let mut sk_bytes = [0_u8; SK_SIZE];
    for i in 0..SK_SIZE {
        sk_bytes[i] = get_sk_byte(i);
    }
    let sk = SecretKey::from_bytes(sk_bytes).unwrap();
    // create ct vec from input parameters
    let mut ct_vec = Vec::new();
    for i in 0..ct_size {
        ct_vec.push(get_ct_byte(i));
    }
    let ct = Ciphertext::from_bytes(&ct_vec).unwrap();
    if !ct.verify() {
        return 0;
    }
    let msg = sk.decrypt(&ct).unwrap();
    for i in 0..msg.len() {
        set_msg_byte(i, msg[i]);
    }
    return msg.len()
}

#[wasm_bindgen]
pub fn generate_poly(threshold: usize) {
    let mut rng = ExternalRng(0);
    let poly = Poly::random(threshold, &mut rng);
    let poly_vec = poly.to_bytes();
    for i in 0..poly_vec.len() {
        set_poly_byte(i, poly_vec[i]);
    }
}

#[wasm_bindgen]
pub fn get_poly_degree(poly_size: usize) -> usize {
    let mut poly_bytes = Vec::new();
    for i in 0..poly_size {
        poly_bytes.push(get_poly_byte(i));
    }
    let poly = Poly::from_bytes(poly_bytes).unwrap();
    poly.degree()
}

#[wasm_bindgen]
pub fn get_mc_degree(mc_size: usize) -> usize {
    let mut mc_bytes = Vec::new();
    for i in 0..mc_size {
        mc_bytes.push(get_mc_byte(i));
    }
    let mc = Commitment::from_bytes(mc_bytes).unwrap();
    mc.degree()
}

#[wasm_bindgen]
pub fn derive_master_key(poly_size: usize) {
    let mut poly_bytes = Vec::new();
    for i in 0..poly_size {
        poly_bytes.push(get_poly_byte(i));
    }
    let poly = Poly::from_bytes(poly_bytes).unwrap();
    let commitment = poly.commitment();
    // see https://github.com/poanetwork/threshold_crypto/blob/7709462f2df487ada3bb3243060504b5881f2628/src/lib.rs#L685
    let mut fr = poly.evaluate(0);
    let msk = SecretKey::from_mut(&mut fr);
    let msk_vec = msk.to_bytes();
    for i in 0..msk_vec.len() {
        set_msk_byte(i, msk_vec[i]);
    }
    //// public key
    // could also use let mpk = msk.public_key();
    let skset: SecretKeySet = SecretKeySet::from(poly);
    let pkset = skset.public_keys();
    let mpk = pkset.public_key();
    let mpk_vec = mpk.to_bytes().to_vec();
    for i in 0..mpk_vec.len() {
        set_mpk_byte(i, mpk_vec[i]);
    }
    // master commitment
    let commitment_vec = commitment.to_bytes();
    for i in 0..commitment_vec.len() {
        set_mc_byte(i, commitment_vec[i]);
    }
}

#[wasm_bindgen]
pub fn derive_key_share(i: usize, poly_size: usize) {
    let mut poly_bytes = Vec::new();
    for i in 0..poly_size {
        poly_bytes.push(get_poly_byte(i));
    }
    let poly = Poly::from_bytes(poly_bytes).unwrap();
    // secret key
    let skset: SecretKeySet = SecretKeySet::from(poly);
    let skshare = skset.secret_key_share(i);
    let skshare_vec = skshare.to_bytes();
    for i in 0..skshare_vec.len() {
        set_skshare_byte(i, skshare_vec[i]);
    }
    // public key
    let pkset = skset.public_keys();
    let pkshare = pkset.public_key_share(i);
    let pkshare_vec = pkshare.to_bytes().to_vec();
    for i in 0..pkshare_vec.len() {
        set_pkshare_byte(i, pkshare_vec[i]);
    }
}

// fills BIVAR_ROW_BYTES and BIVAR_COMMITMENT_BYTES
// with the required number of rows and commitments,
// although not all are necessarily going to be used.
// Values are concatenated into the BYTES vectors.
#[wasm_bindgen]
pub fn generate_bivars(threshold: usize, total_nodes: usize) {
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
        let commitment_vec = commitment.to_bytes();
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
            let row_vec = row.to_bytes();
            for i in 0..row_vec.len() {
                set_bivar_row_byte(i, from_node, to_node, row_vec[i]);
            }
        }
    }
    // save the master commitment
    let mpk_commitment_vec = mpk_commitment.to_bytes();
    for i in 0..mpk_commitment_vec.len() {
        set_mc_byte(i, mpk_commitment_vec[i]);
    }
    // save the group master public key
    let mpkset = PublicKeySet::from(mpk_commitment);
    let mpk = mpkset.public_key();
    let mpk_vec = mpk.to_bytes().to_vec();
    for i in 0..mpk_vec.len() {
        set_mpk_byte(i, mpk_vec[i]);
    }
    // save the master secret key
    let msk_vec = msk.to_bytes();
    for i in 0..msk_vec.len() {
        set_poly_byte(i, msk_vec[i]);
    }
    // save the secret and public key shares
    for node_index in 0..total_nodes {
        let mut sk_val = secret_key_shares[node_index];
        let sk = SecretKeyShare::from_mut(&mut sk_val);
        let sk_vec = sk.to_bytes();
        for i in 0..sk_vec.len() {
            set_bivar_sks_byte(i, node_index, sk_vec[i]);
        }
        let pk = sk.public_key_share();
        let pk_vec = pk.to_bytes().to_vec();
        for i in 0..pk_vec.len() {
            set_bivar_pks_byte(i, node_index, pk_vec[i]);
        }
    }
}

#[wasm_bindgen]
// Depends on MC_BYTES being set to the correct master commitment
// so the PublicKeySet can be created and the signature shares combined.
pub fn combine_signature_shares(total_signatures: usize, commitment_size: usize) {
    // read each signature
    let mut sigs = BTreeMap::new();
    for share_index in 0..total_signatures {
        let index_in_group = get_share_indexes(share_index);
        let mut sig_bytes: [u8; SIG_SIZE] = [0; SIG_SIZE];
        for i in 0..SIG_SIZE {
            let sig_byte = get_signature_share_byte(i, share_index);
            sig_bytes[i] = sig_byte;
        }
        let sig = SignatureShare::from_bytes(sig_bytes).unwrap();
        sigs.insert(index_in_group, sig);
    }
    // read master commitment
    let mut mc_bytes = Vec::new();
    for i in 0..commitment_size {
        let mc_byte = get_mc_byte(i);
        mc_bytes.push(mc_byte);
    }
    let mc = Commitment::from_bytes(mc_bytes).unwrap();
    // Combine signatures.
    let pkset = PublicKeySet::from(mc);
    let combined = pkset.combine_signatures(&sigs).unwrap();
    // set signature bytes
    let combined_vec = combined.to_bytes().to_vec();
    for i in 0..combined_vec.len() {
        set_sig_byte(i, combined_vec[i]);
    }
}

#[wasm_bindgen]
// Assumes secret key share is stored in SK_BYTES
// and ciphertext is stored in CT_BYTES
pub fn create_decryption_share(share_index: usize, ct_size: usize) -> usize {
    // create secret key
    let mut sk_bytes = [0_u8; SK_SIZE];
    for i in 0..SK_SIZE {
        sk_bytes[i] = get_sk_byte(i);
    }
    let sk = SecretKeyShare::from_bytes(sk_bytes).unwrap();
    // create ct vec from input parameters
    let mut ct_vec = Vec::new();
    for i in 0..ct_size {
        ct_vec.push(get_ct_byte(i));
    }
    let ct = Ciphertext::from_bytes(&ct_vec).unwrap();
    // create decryption share
    let decryption_share = sk.decrypt_share(&ct).unwrap();
    // serialize decryption_share
    let dshare_bytes = decryption_share.to_bytes();
    // store decryption_share
    for i in 0..dshare_bytes.len() {
        set_decryption_shares_byte(i, share_index, dshare_bytes[i]);
    }
    // return decryption_share size
    return dshare_bytes.len()
}

#[wasm_bindgen]
pub fn combine_decryption_shares(total_decryption_shares: usize, commitment_size: usize, ct_size: usize) -> usize {
    // read each decryption share
    let mut dshares = BTreeMap::new();
    for share_index in 0..total_decryption_shares {
        let index_in_group = get_share_indexes(share_index);
        let mut dshare_bytes = [0u8; PK_SIZE];
        for i in 0..PK_SIZE {
            let dshare_byte = get_decryption_shares_byte(i, share_index);
            dshare_bytes[i] = dshare_byte;
        }
        let dshare = DecryptionShare::from_bytes(dshare_bytes).unwrap();
        dshares.insert(index_in_group, dshare);
    }
    // read master commitment
    let mut mc_bytes = Vec::new();
    for i in 0..commitment_size {
        let mc_byte = get_mc_byte(i);
        mc_bytes.push(mc_byte);
    }
    let mc = Commitment::from_bytes(mc_bytes).unwrap();
    // create ct vec from input parameters
    let mut ct_vec = Vec::new();
    for i in 0..ct_size {
        ct_vec.push(get_ct_byte(i));
    }
    let ct = Ciphertext::from_bytes(&ct_vec).unwrap();
    // Combine decryption shares.
    let pkset = PublicKeySet::from(mc);
    let msg = pkset.decrypt(&dshares, &ct).unwrap();
    // set message bytes
    for i in 0..msg.len() {
        set_msg_byte(i, msg[i]);
    }
    return msg.len()
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
