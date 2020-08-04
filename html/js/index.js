let DOM = {};
DOM.skToPk = {};
DOM.skToPk.skHex = document.querySelectorAll("#sk-to-pk .skHex")[0];
DOM.skToPk.pkHex = document.querySelectorAll("#sk-to-pk .pkHex")[0];

function skHexToPkHex() {
    DOM.skToPk.pkHex.value = "";
    let skHex = DOM.skToPk.skHex.value.trim();
    if (skHex.length != 64) {
        // TODO show error
        return "";
    }
    let b = hexToUint8Array(skHex);
    // get public key, 48 bytes ie 96 hex chars
    let pkBytes = [];
    for (let i=0; i<48; i++) {
        let pkByte = wasmExports.pk_byte_from_sk(i, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23], b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]);
        pkBytes.push(pkByte);
    }
    let pkHex = uint8ArrayToHex(pkBytes);
    DOM.skToPk.pkHex.value = pkHex;
}

// https://stackoverflow.com/a/50868276
function hexToUint8Array(h) {
    return new Uint8Array(h.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}
function uint8ArrayToHex(a) {
    return a.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}

DOM.skToPk.skHex.addEventListener("input", skHexToPkHex);
