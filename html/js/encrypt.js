(function() {

DOM.encrypt = {};
DOM.encrypt.pk = document.querySelectorAll("#encrypt .pk")[0];
DOM.encrypt.msg = document.querySelectorAll("#encrypt .msg")[0];
DOM.encrypt.ct = document.querySelectorAll("#encrypt .ct")[0];

DOM.encrypt.pk.addEventListener("input", encrypt);
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
        // get public key from UI
        let pkBytes = encoding.parseValue(DOM.encrypt.pk);
        if (pkBytes.length == 0) {
            return;
        }
        if (pkBytes.length != pkLen) {
            let errMsg = errorMessages.pkLength(pkBytes.length);
            encryptError.show(errMsg);
            return;
        }
        // get msg from UI
        let msgBytes = encoding.parseValue(DOM.encrypt.msg);
        if (msgBytes.length == 0) {
            return;
        }
        if (msgBytes.length > maxMsgLen) {
            let errMsg = errorMessages.msgLength(msgBytes.length);
            encryptError.show(errMsg);
            return;
        }
        // encrypt
        let ctBytes = wasmHelpers.encrypt(pkBytes, msgBytes);
        encoding.updateElWithBytes(DOM.encrypt.ct, ctBytes);
    }, 200);
}

})();
