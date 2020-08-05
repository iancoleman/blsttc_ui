// Virtual DOM

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

// threshold_crypto wasm calls

// s is secret key unit8array
function sk_bytes_to_pk_bytes_wasm(s) {
    // set sk bytes
    for (let i=0; i<s.length; i++) {
        wasmExports.set_sk_byte(i, s[i]);
    }
    // convert into pk bytes
    wasmExports.derive_pk_from_sk();
    // read pk bytes
    let pkLen = 48; // bytes
    let pkBytes = [];
    for (let i=0; i<pkLen; i++) {
        let pkByte = wasmExports.get_pk_byte(i);
        pkBytes.push(pkByte);
    }
    return pkBytes;
}

// s is secret key uint8array
// m is message uint8array
function sign_msg_wasm(s, m) {
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
    let sigLen = 96; // bytes
    let sigBytes = [];
    for (let i=0; i<sigLen; i++) {
        let sigByte = wasmExports.get_sig_byte(i);
        sigBytes.push(sigByte);
    }
    return sigBytes;
}

// p is public key uint8array
// s is signature uint8array
// m is message uint8array
function verify_wasm(p, s, m) {
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
    let verified = wasmExports.verify(m.length);
    return verified;
}

// p is public key uint8array
// m is message uint8array
function encrypt_wasm(p, m) {
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
    ctBytes = [];
    for (let i=0; i<ctSize; i++) {
        let ctByte = wasmExports.get_ct_byte(i);
        ctBytes.push(ctByte);
    }
    return ctBytes;
}

// s is secret key uint8array
// c is message uint8array
function decrypt_wasm(s, c) {
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
    msgBytes = [];
    for (let i=0; i<msgSize; i++) {
        let msgByte = wasmExports.get_msg_byte(i);
        msgBytes.push(msgByte);
    }
    return msgBytes;
}

// Encoding conversions

// modified from https://stackoverflow.com/a/11058858
function asciiToUint8Array(a) {
    let b = new Uint8Array(a.length);
    for (let i=0; i<a.length; i++) {
        b[i] = a.charCodeAt(i);
    }
    return b;
}
// https://stackoverflow.com/a/19102224
// TODO resolve RangeError possibility here, see SO comments
function uint8ArrayToAscii(a) {
    return String.fromCharCode.apply(null, a);
}
// https://stackoverflow.com/a/50868276
function hexToUint8Array(h) {
    return new Uint8Array(h.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}
function uint8ArrayToHex(a) {
    return a.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}
// https://stackoverflow.com/a/12713326
function uint8ArrayToBase64(a) {
    return btoa(String.fromCharCode.apply(null, a));
}
function base64ToUint8Array(b) {
    return new Uint8Array(atob(b).split("").map(function(c) {
            return c.charCodeAt(0);
    }));
}

// Event handlers

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

function generateSk() {
    // Warning if no window.crypto available
    if (!window.crypto) {
        alert("Secure randomness not available in this browser.");
        return
    }
    // Clear existing values
    DOM.skToPk.skHex.value = "";
    DOM.skToPk.pkHex.value = "";
    // Not all entropy can be deserialized by threshold_crypto.
    // Try up to ten times until we get a valid sk.
    let max_retries = 20;
    for (let i=0; i<max_retries; i++) {
        try {
            let entropy = new Uint8Array(32);
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
    // clear existing value
    DOM.skToPk.pkHex.value = "";
    // get secret key hex from UI
    let skHex = DOM.skToPk.skHex.value.trim();
    if (skHex.length != 64) {
        // TODO show error
        return "";
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

function signMsg() {
    // clear existing value
    DOM.signMsg.sig.value = "";
    // get secret key hex from UI
    let skHex = DOM.signMsg.skHex.value.trim();
    if (skHex.length != 64) {
        // TODO show error
        return "";
    }
    // convert sk to bytes
    let s = hexToUint8Array(skHex);
    // get msg from UI
    let msg = DOM.signMsg.msg.value; // NB no trim() here
    if (msg.length <= 0 || msg.length > 255) {
        // TODO show error
        return "";
    }
    let m = asciiToUint8Array(msg);
    // get signature
    let sigBytes = sign_msg_wasm(s, m);
    let sigHex = uint8ArrayToHex(sigBytes);
    DOM.signMsg.sig.value = sigHex;
}

function verify() {
    // clear existing value
    DOM.verify.valid.value = "";
    // get public key hex from UI
    let pkHex = DOM.verify.pkHex.value.trim();
    if (pkHex.length != 96) {
        // TODO show error
        return "";
    }
    // convert public key to bytes
    let p = hexToUint8Array(pkHex);
    // get signature hex from UI
    let sigHex = DOM.verify.sig.value.trim();
    if (sigHex.length != 192) {
        // TODO show error
        return "";
    }
    // convert signature to bytes
    let s = hexToUint8Array(sigHex);
    // get msg from UI
    let msg = DOM.verify.msg.value; // NB no trim() here
    if (msg.length <= 0 || msg.length > 255) {
        // TODO show error
        return "";
    }
    let m = asciiToUint8Array(msg);
    // verify
    let valid = verify_wasm(p, s, m);
    DOM.verify.valid.value = valid ? "valid" : "invalid";
}

function encrypt() {
    // clear existing value
    DOM.encrypt.ct.value = "";
    // get public key hex from UI
    let pkHex = DOM.encrypt.pkHex.value.trim();
    if (pkHex.length != 96) {
        // TODO show error
        return "";
    }
    // convert public key to bytes
    let p = hexToUint8Array(pkHex);
    // get msg from UI
    let msg = DOM.encrypt.msg.value; // NB no trim() here
    if (msg.length <= 0 || msg.length > 255) {
        // TODO show error
        return "";
    }
    let m = asciiToUint8Array(msg);
    // encrypt
    let ctBytes = encrypt_wasm(p, m);
    let ctHex = uint8ArrayToHex(ctBytes);
    DOM.encrypt.ct.value = ctHex;
}

function decrypt() {
    // clear existing value
    DOM.decrypt.msg.value = "";
    // get secret key hex from UI
    let skHex = DOM.decrypt.skHex.value.trim();
    if (skHex.length != 64) {
        // TODO show error
        return "";
    }
    // convert secret key to bytes
    let s = hexToUint8Array(skHex);
    // get msg from UI
    let ct = DOM.decrypt.ct.value.trim();
    // TODO decide on max ct length
    if (ct.length <= 0 || ct.length > 10444444) {
        // TODO show error
        return "";
    }
    let c = hexToUint8Array(ct);
    // decrypt
    let msgBytes = decrypt_wasm(s, c);
    let msgAscii = uint8ArrayToAscii(msgBytes);
    DOM.decrypt.msg.value = msgAscii;
}
