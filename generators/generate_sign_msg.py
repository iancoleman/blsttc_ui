skLen = 32 # bytes
maxMsgLen = 256 # bytes

f = """
// BEGIN SIGN_MSG Autogen code

#[wasm_bindgen]
pub fn sign_msg(
    i: usize, // index of byte in signature to return
    l: usize, // number of bytes in message
"""

for i in range(0,skLen):
    f += "    sk_%s: u8,\n" % i

for i in range(0,maxMsgLen):
    if i < maxMsgLen - 1:
        f += "    msg_%s: u8,\n" % i
    else:
        f += "    msg_%s: u8\n" % i

f += """    ) -> u8 {
    // create secret key vec from input parameters
    let sk_bytes = vec![
"""

for i in range(0,skLen):
    if i < skLen - 1:
        f += "        sk_%s,\n" % i
    else:
        f += "        sk_%s\n" % i

f += """    ];
    let sk: SecretKey = bincode::deserialize(&sk_bytes).unwrap();
    // create msg vec from input parameters
    let mut msg = Vec::new();
"""

for i in range(0,maxMsgLen):
    f += """
    if l > %s {
        msg.push(msg_%s);
    }""" % (i, i)

f += """
    let sig = sk.sign(msg);
    return sig.to_bytes().to_vec()[i]
}

// END SIGN_MSG Autogen code
"""

print(f)
