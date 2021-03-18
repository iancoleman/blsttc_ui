(function() {

DOM.signMsg = {};
DOM.signMsg.sk = document.querySelectorAll("#sign-msg .sk")[0];
DOM.signMsg.msg = document.querySelectorAll("#sign-msg .msg")[0];
DOM.signMsg.sig = document.querySelectorAll("#sign-msg .sig")[0];

DOM.signMsg.sk.addEventListener("input", signMsg);
DOM.signMsg.msg.addEventListener("input", signMsg);

let signError = new ErrorDisplay("#sign-msg .error");

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
        // get secret key from UI
        let skBytes = encoding.parseValue(DOM.signMsg.sk);
        if (skBytes.length == 0) {
            return;
        }
        if (skBytes.length != skLen) {
            let errMsg = errorMessages.skLength(skBytes.length);
            signError.show(errMsg);
            return;
        }
        // get msg from UI
        let msgBytes = encoding.parseValue(DOM.signMsg.msg); // NB no trim() here
        if (msgBytes.length <= 0) {
            return
        }
        if (msgBytes.length > maxMsgLen) {
            let errMsg = errorMessages.msgLength(msgBytes.length);
            signError.show(errMsg);
            return;
        }
        // get signature
        let sigBytes = wasmHelpers.sign_msg(skBytes, msgBytes);
        encoding.updateElWithBytes(DOM.signMsg.sig, sigBytes);
    }, 200);
}

})();
