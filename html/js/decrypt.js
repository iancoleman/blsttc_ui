(function() {

DOM.decrypt = {};
DOM.decrypt.skHex = document.querySelectorAll("#decrypt .sk-hex")[0];
DOM.decrypt.ct = document.querySelectorAll("#decrypt .ct")[0];
DOM.decrypt.msg = document.querySelectorAll("#decrypt .msg")[0];

DOM.decrypt.skHex.addEventListener("input", decrypt);
DOM.decrypt.ct.addEventListener("input", decrypt);

decryptError = new ErrorDisplay("#decrypt .error");

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
        let errMsg = errorMessages.skLength(skHex.length);
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
        let errMsg = errorMessages.ctLength(ctHex.length);
        decryptError.show(errMsg);
        return;
    }
    let c = hexToUint8Array(ctHex);
    // decrypt
    let msgBytes = wasmHelpers.decrypt(s, c);
    let msgAscii = uint8ArrayToAscii(msgBytes);
    DOM.decrypt.msg.value = msgAscii;
}

})();
