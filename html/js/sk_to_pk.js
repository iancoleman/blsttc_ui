(function() {

DOM.skToPk = {};
DOM.skToPk.generate = document.querySelectorAll("#sk-to-pk .generate")[0];
DOM.skToPk.sk = document.querySelectorAll("#sk-to-pk .sk")[0];
DOM.skToPk.pk = document.querySelectorAll("#sk-to-pk .pk")[0];

DOM.skToPk.sk.addEventListener("input", skToPk);
DOM.skToPk.generate.addEventListener("click", generateSk);

let deriveError = new ErrorDisplay("#sk-to-pk .error");

function generateSk() {
    // Clear existing values
    DOM.skToPk.sk.value = "";
    DOM.skToPk.pk.value = "";
    // Not all entropy can be deserialized by threshold_crypto.
    // Try up to ten times until we get a valid sk.
    let max_retries = 20;
    for (let i=0; i<max_retries; i++) {
        try {
            let entropy = new Uint8Array(skLen);
            window.crypto.getRandomValues(entropy);
            encoding.updateElWithBytes(DOM.skToPk.sk, entropy);
            skToPk();
            console.log((i+1) + " attempts to generate sk");
            break;
        }
        catch (e) {
            // TODO maybe log a message if more than max_retries attempted?
        }
    }
}

function skToPk() {
    deriveError.hide();
    // if already using wasm buffers, try again later
    if (isWasming) {
        setTimeout(skToPk, 200);
        return;
    }
    // clear existing value
    DOM.skToPk.pk.value = "";
    // get secret key value from UI
    let skBytes = encoding.parseValue(DOM.skToPk.sk);
    if (skBytes.length == 0) {
        return;
    }
    if (skBytes.length != skLen) {
        let errMsg = errorMessages.skLength(skBytes.length);
        deriveError.show(errMsg);
        return;
    }
    // get public key from sk, will be 48 bytes ie 96 hex chars
    let pkBytes = wasmHelpers.sk_bytes_to_pk_bytes(skBytes);
    // display pk
    encoding.updateElWithBytes(DOM.skToPk.pk, pkBytes);
}

})();
