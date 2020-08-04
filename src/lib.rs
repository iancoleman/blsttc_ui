use wasm_bindgen::prelude::*;
use threshold_crypto::{serde_impl::SerdeSecret, SecretKey};

#[wasm_bindgen]
pub fn pk_byte_from_sk(
    i: usize,
    sk_0: u8,
    sk_1: u8,
    sk_2: u8,
    sk_3: u8,
    sk_4: u8,
    sk_5: u8,
    sk_6: u8,
    sk_7: u8,
    sk_8: u8,
    sk_9: u8,
    sk_10: u8,
    sk_11: u8,
    sk_12: u8,
    sk_13: u8,
    sk_14: u8,
    sk_15: u8,
    sk_16: u8,
    sk_17: u8,
    sk_18: u8,
    sk_19: u8,
    sk_20: u8,
    sk_21: u8,
    sk_22: u8,
    sk_23: u8,
    sk_24: u8,
    sk_25: u8,
    sk_26: u8,
    sk_27: u8,
    sk_28: u8,
    sk_29: u8,
    sk_30: u8,
    sk_31: u8
    ) -> u8 {
    let sk_bytes = vec![sk_0, sk_1, sk_2, sk_3, sk_4, sk_5, sk_6, sk_7, sk_8, sk_9, sk_10, sk_11, sk_12, sk_13, sk_14, sk_15, sk_16, sk_17, sk_18, sk_19, sk_20, sk_21, sk_22, sk_23, sk_24, sk_25, sk_26, sk_27, sk_28, sk_29, sk_30, sk_31];
    let sk: SecretKey = bincode::deserialize(&sk_bytes).unwrap();
    let b = sk.public_key().to_bytes().to_vec()[i];
    return b
}

#[wasm_bindgen]
pub fn sk_byte_at_index(i: usize) -> u8 {
    // start with hex
    let sk_hex = "7b4ecc05ecc292110029b0d099994505dd74d84197f995bd9c41fc0843fe201b";
    let pk_hex = "a32fc9479cb20e28326952a8acdb76194e44f1f20a39c787265f54af3611e4db80ebece61638ea42b960289e17a13e97";
    // convert to secret key
    let sk_bytes = parse_hex(&sk_hex);
    let sk: SecretKey = bincode::deserialize(&sk_bytes).unwrap();
    // convert from secret key to bytes
    let sk_response = bincode::serialize(&SerdeSecret(sk)).unwrap();
    // respond with byte at index i from input parameter
    let b = sk_response[i];
    //let b = sk.public_key().to_bytes().to_vec()[2];
    return b
}

fn parse_hex(hex_str: &str) -> Vec<u8> {
    let mut hex_bytes = hex_str
        .as_bytes()
        .iter()
        .filter_map(|b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        })
        .fuse();

    let mut bytes = Vec::new();
    while let (Some(h), Some(l)) = (hex_bytes.next(), hex_bytes.next()) {
        bytes.push(h<<4 | l)
    }
    bytes
}

fn vec_to_hex(v: Vec<u8>) -> String {
    v.iter().map(|b| format!("{:02x}", b)).collect()
}
