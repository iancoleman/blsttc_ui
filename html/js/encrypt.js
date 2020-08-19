(function() {

DOM.encrypt = {};
DOM.encrypt.pkHex = document.querySelectorAll("#encrypt .pk-hex")[0];
DOM.encrypt.msg = document.querySelectorAll("#encrypt .msg")[0];
DOM.encrypt.ct = document.querySelectorAll("#encrypt .ct")[0];

DOM.encrypt.pkHex.addEventListener("input", encrypt);
DOM.encrypt.msg.addEventListener("input", encrypt);

encryptError = new ErrorDisplay("#encrypt .error");

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
            let errMsg = errorMessages.pkLength(pkHex.length);
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
            let errMsg = errorMessages.msgLength(msg.length);
            encryptError.show(errMsg);
            return;
        }
        let m = asciiToUint8Array(msg);
        // encrypt
        let ctBytes = wasmHelpers.encrypt(p, m);
        let ctHex = uint8ArrayToHex(ctBytes);
        DOM.encrypt.ct.value = ctHex;
    }, 200);
}

})();
