///////////////
// Contants
///////////////

const skLen = 32; // bytes
const pkLen = 48; // bytes
const sigLen = 96; // bytes
const maxMsgLen = 1049600; // bytes
const maxCtLen = 1049600; // bytes

///////////////
// Virtual DOM
///////////////

let DOM = {};
DOM.skToPk = {};
DOM.skToPk.generate = document.querySelectorAll("#sk-to-pk .generate")[0];
DOM.skToPk.skHex = document.querySelectorAll("#sk-to-pk .sk-hex")[0];
DOM.skToPk.pkHex = document.querySelectorAll("#sk-to-pk .pk-hex")[0];
DOM.signMsg = {};
DOM.signMsg.skHex = document.querySelectorAll("#sign-msg .sk-hex")[0];
DOM.signMsg.msg = document.querySelectorAll("#sign-msg .msg")[0];
DOM.signMsg.sig = document.querySelectorAll("#sign-msg .sig")[0];
DOM.verify = {};
DOM.verify.pkHex = document.querySelectorAll("#verify .pk-hex")[0];
DOM.verify.msg = document.querySelectorAll("#verify .msg")[0];
DOM.verify.sig = document.querySelectorAll("#verify .sig")[0];
DOM.verify.valid = document.querySelectorAll("#verify .valid")[0];
DOM.encrypt = {};
DOM.encrypt.pkHex = document.querySelectorAll("#encrypt .pk-hex")[0];
DOM.encrypt.msg = document.querySelectorAll("#encrypt .msg")[0];
DOM.encrypt.ct = document.querySelectorAll("#encrypt .ct")[0];
DOM.decrypt = {};
DOM.decrypt.skHex = document.querySelectorAll("#decrypt .sk-hex")[0];
DOM.decrypt.ct = document.querySelectorAll("#decrypt .ct")[0];
DOM.decrypt.msg = document.querySelectorAll("#decrypt .msg")[0];
DOM.stk = {}; // simple threshold keys
DOM.stk.generate = document.querySelectorAll("#simple-threshold-keys .generate")[0];
DOM.stk.threshold = document.querySelectorAll("#simple-threshold-keys .threshold")[0];
DOM.stk.polyHex = document.querySelectorAll("#simple-threshold-keys .poly-hex")[0];
DOM.stk.mskHex = document.querySelectorAll("#simple-threshold-keys .msk-hex")[0];
DOM.stk.mpkHex = document.querySelectorAll("#simple-threshold-keys .mpk-hex")[0];
DOM.stk.totalKeys = document.querySelectorAll("#simple-threshold-keys .total-keys")[0];
DOM.stk.skset = document.querySelectorAll("#simple-threshold-keys .skset")[0];
DOM.stk.pkset = document.querySelectorAll("#simple-threshold-keys .pkset")[0];

///////////////
// Event handlers
///////////////

DOM.skToPk.skHex.addEventListener("input", skHexToPkHex);
DOM.skToPk.generate.addEventListener("click", generateSk);
DOM.signMsg.skHex.addEventListener("input", signMsg);
DOM.signMsg.msg.addEventListener("input", signMsg);
DOM.verify.pkHex.addEventListener("input", verify);
DOM.verify.msg.addEventListener("input", verify);
DOM.verify.sig.addEventListener("input", verify);
DOM.encrypt.pkHex.addEventListener("input", encrypt);
DOM.encrypt.msg.addEventListener("input", encrypt);
DOM.decrypt.skHex.addEventListener("input", decrypt);
DOM.decrypt.ct.addEventListener("input", decrypt);
DOM.stk.generate.addEventListener("click", generatePoly);
DOM.stk.polyHex.addEventListener("input", deriveStk);
DOM.stk.totalKeys.addEventListener("input", deriveStk);

///////////////
// threshold_crypto wasm calls
///////////////

let isWasming = false;

// s is secret key unit8array
function sk_bytes_to_pk_bytes_wasm(s) {
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
function sign_msg_wasm(s, m) {
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
function verify_wasm(p, s, m) {
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

function set_rng_values_wasm() {
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
function encrypt_wasm(p, m) {
    isWasming = true;
    let ctBytes = [];
    try {
        set_rng_values_wasm();
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
function decrypt_wasm(s, c) {
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

function generate_poly_wasm(threshold) {
    set_rng_values_wasm();
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

function get_msk_bytes_wasm() {
    let mskBytes = [];
    for (let i=0; i<skLen; i++) {
        let mskByte = wasmExports.get_msk_byte(i);
        mskBytes.push(mskByte);
    }
    return mskBytes;
}

function get_mpk_bytes_wasm() {
    let mpkBytes = [];
    for (let i=0; i<pkLen; i++) {
        let mpkByte = wasmExports.get_mpk_byte(i);
        mpkBytes.push(mpkByte);
    }
    return mpkBytes;
}

function get_skshare_wasm() {
    let skshareBytes = [];
    for (let i=0; i<skLen; i++) {
        let skshareByte = wasmExports.get_skshare_byte(i);
        skshareBytes.push(skshareByte);
    }
    return skshareBytes;
}

function get_pkshare_wasm() {
    let pkshareBytes = [];
    for (let i=0; i<pkLen; i++) {
        let pkshareByte = wasmExports.get_pkshare_byte(i);
        pkshareBytes.push(pkshareByte);
    }
    return pkshareBytes;
}

///////////////
// Handler methods
///////////////

function generateSk() {
    // Clear existing values
    DOM.skToPk.skHex.value = "";
    DOM.skToPk.pkHex.value = "";
    // Not all entropy can be deserialized by threshold_crypto.
    // Try up to ten times until we get a valid sk.
    let max_retries = 20;
    for (let i=0; i<max_retries; i++) {
        try {
            let entropy = new Uint8Array(skLen);
            window.crypto.getRandomValues(entropy);
            let h = uint8ArrayToHex(entropy);
            DOM.skToPk.skHex.value = h;
            skHexToPkHex();
            console.log((i+1) + " attempts to generate sk");
            break;
        }
        catch (e) {
            // TODO maybe log a message if more than max_retries attempted?
        }
    }
}

function skHexToPkHex() {
    deriveError.hide();
    // if already using wasm buffers, try again later
    if (isWasming) {
        setTimeout(skHexToPkHex, 200);
        return;
    }
    // clear existing value
    DOM.skToPk.pkHex.value = "";
    // get secret key hex from UI
    let skHex = DOM.skToPk.skHex.value.trim();
    if (skHex.length == 0) {
        return;
    }
    if (skHex.length != skLen * 2) {
        let errMsg = skErrMsg(skHex.length);
        deriveError.show(errMsg);
        return;
    }
    // convert sk to bytes
    let b = hexToUint8Array(skHex);
    // get public key from sk, will be 48 bytes ie 96 hex chars
    let pkBytes = sk_bytes_to_pk_bytes_wasm(b);
    // convert pk to hex
    let pkHex = uint8ArrayToHex(pkBytes);
    // show in UI
    DOM.skToPk.pkHex.value = pkHex;
}

let signDebounce = null;
function signMsg() {
    signError.hide();
    // if already using wasm buffers, try again later
    if (isWasming) {
        setTimeout(signMsg, 200);
        return;
    }
    // if typing is happening quickly wait until it stops.
    if (signDebounce != null) {
        clearTimeout(signDebounce);
    }
    signDebounce = setTimeout(function() {
        // clear existing value
        DOM.signMsg.sig.value = "";
        // get secret key hex from UI
        let skHex = DOM.signMsg.skHex.value.trim();
        if (skHex.length == 0) {
            return;
        }
        if (skHex.length != skLen * 2) {
            let errMsg = skErrMsg(skHex.length);
            signError.show(errMsg);
            return;
        }
        // convert sk to bytes
        let s = hexToUint8Array(skHex);
        // get msg from UI
        let msg = DOM.signMsg.msg.value; // NB no trim() here
        if (msg.length <= 0) {
            return
        }
        if (msg.length > maxMsgLen) {
            let errMsg = msgErrMsg(msg.length);
            signError.show(errMsg);
            return;
        }
        let m = asciiToUint8Array(msg);
        // get signature
        let sigBytes = sign_msg_wasm(s, m);
        let sigHex = uint8ArrayToHex(sigBytes);
        DOM.signMsg.sig.value = sigHex;
    }, 200);
}

let verifyDebounce = null;
function verify() {
    verifyError.hide();
    // if already using wasm buffers, try again later
    if (isWasming) {
        setTimeout(verify, 200);
        return;
    }
    // if typing is happening quickly wait until it stops.
    if (verifyDebounce != null) {
        clearTimeout(verifyDebounce);
    }
    verifyDebounce = setTimeout(function() {
        // clear existing value
        DOM.verify.valid.value = "";
        // get public key hex from UI
        let pkHex = DOM.verify.pkHex.value.trim();
        if (pkHex.length == 0) {
            return;
        }
        if (pkHex.length != pkLen * 2) {
            let errMsg = pkErrMsg(pkHex.length);
            verifyError.show(errMsg);
            return;
        }
        // convert public key to bytes
        let p = hexToUint8Array(pkHex);
        // get signature hex from UI
        let sigHex = DOM.verify.sig.value.trim();
        if (sigHex.length == 0) {
            return;
        }
        if (sigHex.length != 192) {
            let errMsg = sigErrMsg(sigHex.length);
            verifyError.show(errMsg);
            return;
        }
        // convert signature to bytes
        let s = hexToUint8Array(sigHex);
        // get msg from UI
        let msg = DOM.verify.msg.value; // NB no trim() here
        if (msg.length == 0) {
            return;
        }
        if (msg.length > maxMsgLen) {
            let errMsg = msgErrMsg(msg.length);
            verifyError.show(errMsg);
            return;
        }
        let m = asciiToUint8Array(msg);
        // verify
        let valid = verify_wasm(p, s, m);
        DOM.verify.valid.value = valid ? "valid" : "invalid";
    }, 200);
}

let encryptDebounce = null;
function encrypt() {
    encryptError.hide();
    // if already using wasm buffers, try again later
    if (isWasming) {
        setTimeout(encrypt, 200);
        return;
    }
    // if typing is happening quickly wait until it stops.
    if (encryptDebounce != null) {
        clearTimeout(encryptDebounce);
    }
    encryptDebounce = setTimeout(function() {
        // clear existing value
        DOM.encrypt.ct.value = "";
        // get public key hex from UI
        let pkHex = DOM.encrypt.pkHex.value.trim();
        if (pkHex.length == 0) {
            return;
        }
        if (pkHex.length != pkLen * 2) {
            let errMsg = pkErrMsg(pkHex.length);
            encryptError.show(errMsg);
            return;
        }
        // convert public key to bytes
        let p = hexToUint8Array(pkHex);
        // get msg from UI
        let msg = DOM.encrypt.msg.value; // NB no trim() here
        if (msg.length == 0) {
            return;
        }
        if (msg.length > maxMsgLen) {
            let errMsg = msgErrMsg(msg.length);
            encryptError.show(errMsg);
            return;
        }
        let m = asciiToUint8Array(msg);
        // encrypt
        let ctBytes = encrypt_wasm(p, m);
        let ctHex = uint8ArrayToHex(ctBytes);
        DOM.encrypt.ct.value = ctHex;
    }, 200);
}

function decrypt() {
    decryptError.hide();
    // if already using wasm buffers, try again later
    if (isWasming) {
        setTimeout(decrypt, 200);
        return;
    }
    // clear existing value
    DOM.decrypt.msg.value = "";
    // get secret key hex from UI
    let skHex = DOM.decrypt.skHex.value.trim();
    if (skHex.length == 0) {
        return;
    }
    if (skHex.length != skLen * 2) {
        let errMsg = skErrMsg(skHex.length);
        decryptError.show(errMsg);
        return;
    }
    // convert secret key to bytes
    let s = hexToUint8Array(skHex);
    // get msg from UI
    let ctHex = DOM.decrypt.ct.value.trim();
    if (ctHex.length == 0) {
        return;
    }
    if (ctHex.length > maxCtLen * 2) {
        let errMsg = ctErrMsg(ctHex.length);
        decryptError.show(errMsg);
        return;
    }
    let c = hexToUint8Array(ctHex);
    // decrypt
    let msgBytes = decrypt_wasm(s, c);
    let msgAscii = uint8ArrayToAscii(msgBytes);
    DOM.decrypt.msg.value = msgAscii;
}

function generatePoly() {
    let threshold = parseInt(DOM.stk.threshold.value);
    let polyBytes = generate_poly_wasm(threshold);
    let polyHex = uint8ArrayToHex(polyBytes);
    DOM.stk.polyHex.value = polyHex;
    deriveStk();
}

function deriveStk() {
    // set poly in wasm
    let polyHex = DOM.stk.polyHex.value;
    let polyBytes = hexToUint8Array(polyHex);
    for (let i=0; i<polyBytes.length; i++) {
        let v = polyBytes[i];
        wasmExports.set_poly_byte(i, v);
    }
    // get threshold
    let threshold = wasmExports.get_poly_degree();
    DOM.stk.threshold.value = threshold;
    // derive master keys, ie index 0
    let mkIndex = 0;
    wasmExports.derive_master_key();
    // show master secret key
    let mskBytes = get_msk_bytes_wasm();
    let mskHex = uint8ArrayToHex(mskBytes);
    DOM.stk.mskHex.value = mskHex;
    // show master public key
    let mpkBytes = get_mpk_bytes_wasm();
    let mpkHex = uint8ArrayToHex(mpkBytes);
    DOM.stk.mpkHex.value = mpkHex;
    // derive keys, ie index 1 to N
    let n = parseInt(DOM.stk.totalKeys.value);
    let skshares = "";
    let pkshares = "";
    for (let i=0; i<n; i++) {
        wasmExports.derive_key_share(i);
        let skshareBytes = get_skshare_wasm();
        let skshareHex = uint8ArrayToHex(skshareBytes);
        skshares += skshareHex + "\n";
        // show master public key
        let pkshareBytes = get_pkshare_wasm();
        let pkshareHex = uint8ArrayToHex(pkshareBytes);
        pkshares += pkshareHex + "\n";
    }
    DOM.stk.skset.value = skshares.trim();
    DOM.stk.pkset.value = pkshares.trim();
}
