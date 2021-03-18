(function() {

DOM.decrypt = {};
DOM.decrypt.sk = document.querySelectorAll("#decrypt .sk")[0];
DOM.decrypt.ct = document.querySelectorAll("#decrypt .ct")[0];
DOM.decrypt.msg = document.querySelectorAll("#decrypt .msg")[0];

DOM.decrypt.sk.addEventListener("input", decrypt);
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
    // get secret key from UI
    let skBytes = encoding.parseValue(DOM.decrypt.sk);
    if (skBytes.length == 0) {
        return;
    }
    if (skBytes.length != skLen) {
        let errMsg = errorMessages.skLength(skBytes.length);
        decryptError.show(errMsg);
        return;
    }
    // get msg from UI
    let ctBytes = encoding.parseValue(DOM.decrypt.ct);
    if (ctBytes.length == 0) {
        return;
    }
    if (ctBytes.length > maxCtLen) {
        let errMsg = errorMessages.ctLength(ctBytes.length);
        decryptError.show(errMsg);
        return;
    }
    // decrypt
    let msgBytes = wasmHelpers.decrypt(skBytes, ctBytes);
    encoding.updateElWithBytes(DOM.decrypt.msg, msgBytes);
}

})();
