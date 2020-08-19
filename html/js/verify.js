(function() {

DOM.verify = {};
DOM.verify.pkHex = document.querySelectorAll("#verify .pk-hex")[0];
DOM.verify.msg = document.querySelectorAll("#verify .msg")[0];
DOM.verify.sig = document.querySelectorAll("#verify .sig")[0];
DOM.verify.valid = document.querySelectorAll("#verify .valid")[0];

DOM.verify.pkHex.addEventListener("input", verify);
DOM.verify.msg.addEventListener("input", verify);
DOM.verify.sig.addEventListener("input", verify);

verifyError = new ErrorDisplay("#verify .error");

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
            let errMsg = errorMessages.pkLength(pkHex.length);
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
        let valid = wasmHelpers.verify(p, s, m);
        DOM.verify.valid.value = valid ? "valid" : "invalid";
    }, 200);
}

})();
