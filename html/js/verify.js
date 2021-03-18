(function() {

DOM.verify = {};
DOM.verify.pk = document.querySelectorAll("#verify .pk")[0];
DOM.verify.msg = document.querySelectorAll("#verify .msg")[0];
DOM.verify.sig = document.querySelectorAll("#verify .sig")[0];
DOM.verify.valid = document.querySelectorAll("#verify .valid")[0];

DOM.verify.pk.addEventListener("input", verify);
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
        // get public key from UI
        let pkBytes = encoding.parseValue(DOM.verify.pk);
        if (pkBytes.length == 0) {
            return;
        }
        if (pkBytes.length != pkLen) {
            let errMsg = errorMessages.pkLength(pkBytes.length);
            verifyError.show(errMsg);
            return;
        }
        // get signature from UI
        let sigBytes = encoding.parseValue(DOM.verify.sig);
        if (sigBytes.length == 0) {
            return;
        }
        if (sigBytes.length != 96) {
            let errMsg = errorMessages.sigLength(sigBytes.length);
            verifyError.show(errMsg);
            return;
        }
        // get msg from UI
        let msgBytes = encoding.parseValue(DOM.verify.msg);
        if (msgBytes.length == 0) {
            return;
        }
        if (msgBytes.length > maxMsgLen) {
            let errMsg = msgErrMsg(msgBytes.length);
            verifyError.show(errMsg);
            return;
        }
        // verify
        let valid = wasmHelpers.verify(pkBytes, sigBytes, msgBytes);
        DOM.verify.valid.value = valid ? "valid" : "invalid";
    }, 200);
}

})();
