// threshold_crypto wasm calls. Since they operate on single bytes at a time
// it's handy to have helpers to do the required looping.

let isWasming = false;

let wasmHelpers = new (function() {

// s is secret key unit8array
this.sk_bytes_to_pk_bytes = function(s) {
    isWasming = true;
    let pkBytes = [];
    try {
        // set sk bytes
        for (let i=0; i<s.length; i++) {
            wasmExports.set_sk_byte(i, s[i]);
        }
        // convert into pk bytes
        wasmExports.derive_pk_from_sk();
        // read pk bytes
        for (let i=0; i<pkLen; i++) {
            let pkByte = wasmExports.get_pk_byte(i);
            pkBytes.push(pkByte);
        }
    }
    catch (e) {
        isWasming = false;
        throw("Failed to generate");
    }
    isWasming = false;
    return pkBytes;
}

// s is secret key uint8array
// m is message uint8array
this.sign_msg = function(s, m) {
    isWasming = true;
    let sigBytes = [];
    try {
        // set secret key bytes
        for (let i=0; i<s.length; i++) {
            wasmExports.set_sk_byte(i, s[i]);
        }
        // set message bytes
        for (let i=0; i<m.length; i++) {
            wasmExports.set_msg_byte(i, m[i]);
        }
        // sign message
        wasmExports.sign_msg(m.length);
        // get signature bytes
        for (let i=0; i<sigLen; i++) {
            let sigByte = wasmExports.get_sig_byte(i);
            sigBytes.push(sigByte);
        }
    }
    catch (e) {
        isWasming = false;
    }
    isWasming = false;
    return sigBytes;
}

// p is public key uint8array
// s is signature uint8array
// m is message uint8array
this.verify = function(p, s, m) {
    isWasming = true;
    let verified = false;
    try {
        // set public key bytes
        for (let i=0; i<p.length; i++) {
            wasmExports.set_pk_byte(i, p[i]);
        }
        // set signature bytes
        for (let i=0; i<s.length; i++) {
            wasmExports.set_sig_byte(i, s[i]);
        }
        // set message bytes
        for (let i=0; i<m.length; i++) {
            wasmExports.set_msg_byte(i, m[i]);
        }
        verified = wasmExports.verify(m.length);
    }
    catch (e) {
        isWasming = false;
    }
    isWasming = false;
    return verified;
}

this.set_rng_values = function() {
    // Warning if no window.crypto available
    if (!window.crypto) {
        alert("Secure randomness not available in this browser, output is insecure.");
        return
    }
    let RNG_VALUES_SIZE = wasmExports.get_rng_values_size();
    let rngValues = new Uint32Array(RNG_VALUES_SIZE);
    window.crypto.getRandomValues(rngValues);
    for (let i=0; i<rngValues.length; i++) {
        wasmExports.set_rng_value(i, rngValues[i]);
    }
}

// p is public key uint8array
// m is message uint8array
this.encrypt = function(p, m) {
    isWasming = true;
    let ctBytes = [];
    try {
        wasmHelpers.set_rng_values();
        // set public key bytes
        for (let i=0; i<p.length; i++) {
            wasmExports.set_pk_byte(i, p[i]);
        }
        // set message bytes
        for (let i=0; i<m.length; i++) {
            wasmExports.set_msg_byte(i, m[i]);
        }
        // generate strong random u64 used by encrypt
        let entropy = new Uint32Array(2);
        window.crypto.getRandomValues(entropy);
        let r1 = entropy[0];
        let r2 = entropy[1];
        // encrypt the message
        let ctSize = wasmExports.encrypt(m.length, r1, r2);
        // get ciphertext bytes
        for (let i=0; i<ctSize; i++) {
            let ctByte = wasmExports.get_ct_byte(i);
            ctBytes.push(ctByte);
        }
    }
    catch (e) {
        isWasming = false;
    }
    isWasming = false;
    return ctBytes;
}

// s is secret key uint8array
// c is message uint8array
this.decrypt = function(s, c) {
    isWasming = true;
    let msgBytes = [];
    try {
        // set secret key bytes
        for (let i=0; i<s.length; i++) {
            wasmExports.set_sk_byte(i, s[i]);
        }
        // set ciphertext bytes
        for (let i=0; i<c.length; i++) {
            wasmExports.set_ct_byte(i, c[i]);
        }
        let msgSize = wasmExports.decrypt(c.length);
        // get message bytes
        for (let i=0; i<msgSize; i++) {
            let msgByte = wasmExports.get_msg_byte(i);
            msgBytes.push(msgByte);
        }
    }
    catch (e) {
        isWasming = false;
    }
    isWasming = false;
    return msgBytes;
}

this.generate_poly = function(threshold) {
    wasmHelpers.set_rng_values();
    let entropy = new Uint32Array(2);
    window.crypto.getRandomValues(entropy);
    let r1 = entropy[0];
    let r2 = entropy[1];
    let polySize = wasmExports.generate_poly(threshold, r1, r2);
    let polyBytes = [];
    for (let i=0; i<polySize; i++) {
        let polyByte = wasmExports.get_poly_byte(i);
        polyBytes.push(polyByte);
    }
    return polyBytes;
}

this.get_msk_bytes = function() {
    let mskBytes = [];
    for (let i=0; i<skLen; i++) {
        let mskByte = wasmExports.get_msk_byte(i);
        mskBytes.push(mskByte);
    }
    return mskBytes;
}

this.get_mpk_bytes = function() {
    let mpkBytes = [];
    for (let i=0; i<pkLen; i++) {
        let mpkByte = wasmExports.get_mpk_byte(i);
        mpkBytes.push(mpkByte);
    }
    return mpkBytes;
}

this.get_skshare = function() {
    let skshareBytes = [];
    for (let i=0; i<skLen; i++) {
        let skshareByte = wasmExports.get_skshare_byte(i);
        skshareBytes.push(skshareByte);
    }
    return skshareBytes;
}

this.get_pkshare = function() {
    let pkshareBytes = [];
    for (let i=0; i<pkLen; i++) {
        let pkshareByte = wasmExports.get_pkshare_byte(i);
        pkshareBytes.push(pkshareByte);
    }
    return pkshareBytes;
}

})();
