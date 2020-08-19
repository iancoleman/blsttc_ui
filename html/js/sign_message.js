(function() {

DOM.signMsg = {};
DOM.signMsg.skHex = document.querySelectorAll("#sign-msg .sk-hex")[0];
DOM.signMsg.msg = document.querySelectorAll("#sign-msg .msg")[0];
DOM.signMsg.sig = document.querySelectorAll("#sign-msg .sig")[0];

DOM.signMsg.skHex.addEventListener("input", signMsg);
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
        // get secret key hex from UI
        let skHex = DOM.signMsg.skHex.value.trim();
        if (skHex.length == 0) {
            return;
        }
        if (skHex.length != skLen * 2) {
            let errMsg = errorMessages.skLength(skHex.length);
            signError.show(errMsg);
            return;
        }
        // convert sk to bytes
        let s = hexToUint8Array(skHex);
        // get msg from UI
        let msg = DOM.signMsg.msg.value; // NB no trim() here
        if (msg.length <= 0) {
            return
        }
        if (msg.length > maxMsgLen) {
            let errMsg = errorMessages.msgLength(msg.length);
            signError.show(errMsg);
            return;
        }
        let m = asciiToUint8Array(msg);
        // get signature
        let sigBytes = wasmHelpers.sign_msg(s, m);
        let sigHex = uint8ArrayToHex(sigBytes);
        DOM.signMsg.sig.value = sigHex;
    }, 200);
}

})();
