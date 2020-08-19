(function() {

DOM.skToPk = {};
DOM.skToPk.generate = document.querySelectorAll("#sk-to-pk .generate")[0];
DOM.skToPk.skHex = document.querySelectorAll("#sk-to-pk .sk-hex")[0];
DOM.skToPk.pkHex = document.querySelectorAll("#sk-to-pk .pk-hex")[0];

DOM.skToPk.skHex.addEventListener("input", skHexToPkHex);
DOM.skToPk.generate.addEventListener("click", generateSk);

let deriveError = new ErrorDisplay("#sk-to-pk .error");

function generateSk() {
    // Clear existing values
    DOM.skToPk.skHex.value = "";
    DOM.skToPk.pkHex.value = "";
    // Not all entropy can be deserialized by threshold_crypto.
    // Try up to ten times until we get a valid sk.
    let max_retries = 20;
    for (let i=0; i<max_retries; i++) {
        try {
            let entropy = new Uint8Array(skLen);
            window.crypto.getRandomValues(entropy);
            let h = uint8ArrayToHex(entropy);
            DOM.skToPk.skHex.value = h;
            skHexToPkHex();
            console.log((i+1) + " attempts to generate sk");
            break;
        }
        catch (e) {
            // TODO maybe log a message if more than max_retries attempted?
        }
    }
}

function skHexToPkHex() {
    deriveError.hide();
    // if already using wasm buffers, try again later
    if (isWasming) {
        setTimeout(skHexToPkHex, 200);
        return;
    }
    // clear existing value
    DOM.skToPk.pkHex.value = "";
    // get secret key hex from UI
    let skHex = DOM.skToPk.skHex.value.trim();
    if (skHex.length == 0) {
        return;
    }
    if (skHex.length != skLen * 2) {
        let errMsg = errorMessages.skLength(skHex.length);
        deriveError.show(errMsg);
        return;
    }
    // convert sk to bytes
    let b = hexToUint8Array(skHex);
    // get public key from sk, will be 48 bytes ie 96 hex chars
    let pkBytes = wasmHelpers.sk_bytes_to_pk_bytes(b);
    // convert pk to hex
    let pkHex = uint8ArrayToHex(pkBytes);
    // show in UI
    DOM.skToPk.pkHex.value = pkHex;
}

})();
