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

function uint8ArrayToBase32z(a) {
    for (let i=0; i<a.length; i++) {
        wasmExports.set_unbase32z_byte(i, a[i]);
    }
    let b32zSize = wasmExports.base32z_encode(a.length);
    let b32zBytes = [];
    for (let i=0; i<b32zSize; i++) {
        let b = wasmExports.get_base32z_byte(i);
        b32zBytes.push(b);
    }
    return b32zBytes;
}

function base32zToUin8array(b) {
    for (let i=0; i<b.length; i++) {
        wasmExports.set_base32z_byte(i, b[i]);
    }
    let unb32zSize = wasmExports.base32z_decode(b.length);
    let unb32zBytes = [];
    for (let i=0; i<unb32zSize; i++) {
        let b = wasmExports.get_unbase32z_byte(i);
        unb32zBytes.push(b);
    }
    return unb32zBytes;
}
