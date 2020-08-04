pkLen = 48 # bytes
sigLen = 96 # bytes
maxMsgLen = 256 # bytes

f = """
// BEGIN VERIFY Autogen code

#[wasm_bindgen]
pub fn verify(
    l: usize, // number of bytes in message
"""

for i in range(0,pkLen):
    f += "    pk_%s: u8,\n" % i

for i in range(0,sigLen):
    f += "    sig_%s: u8,\n" % i

for i in range(0,maxMsgLen):
    if i < maxMsgLen - 1:
        f += "    msg_%s: u8,\n" % i
    else:
        f += "    msg_%s: u8\n" % i

f += """    ) -> bool {
    // create public key vec from input parameters
    let pk_bytes: [u8; 48] = [
"""

for i in range(0,pkLen):
    if i < pkLen - 1:
        f += "        pk_%s,\n" % i
    else:
        f += "        pk_%s\n" % i

f += """    ];
    let pk = PublicKey::from_bytes(pk_bytes).unwrap();
    // create signature vec from input parameters
    let sig_bytes: [u8; 96] = [
"""

for i in range(0,sigLen):
    if i < sigLen - 1:
        f += "        sig_%s,\n" % i
    else:
        f += "        sig_%s\n" % i

f += """    ];
    let sig = Signature::from_bytes(sig_bytes).unwrap();
    // create msg vec from input parameters
    let mut msg = Vec::new();
"""

for i in range(0,maxMsgLen):
    f += """
    if l > %s {
        msg.push(msg_%s);
    }""" % (i, i)

f += """
    return pk.verify(&sig, msg)
}

// END VERIFY Autogen code
"""

print(f)
