(function() {

DOM.sgm = document.querySelectorAll("#thresh-sig")[0];
DOM.sgm.skshares = DOM.sgm.querySelectorAll(".skshares")[0];
DOM.sgm.mcHex = DOM.sgm.querySelectorAll(".mc-hex")[0];
DOM.sgm.msg = DOM.sgm.querySelectorAll(".msg")[0];
DOM.sgm.sigshares = DOM.sgm.querySelectorAll(".sig-shares")[0];
DOM.sgm.sig = DOM.sgm.querySelectorAll(".sig")[0];

DOM.sgm.skshares.addEventListener("input", tryToSign);
DOM.sgm.mcHex.addEventListener("input", tryToSign);
DOM.sgm.msg.addEventListener("input", tryToSign);

let sgmDebounce = null;
function tryToSign() {
    // if already using wasm buffers, try again later
    if (isWasming) {
        setTimeout(tryToSign, 200);
        return;
    }
    // if typing is happening quickly wait until it stops.
    if (sgmDebounce != null) {
        clearTimeout(sgmDebounce);
    }
    sgmDebounce = setTimeout(function() {
        // clear existing values
        DOM.sgm.sigshares.value = "";
        DOM.sgm.sig.value = "";
        // get message from UI
        let msg = DOM.sgm.msg.value;
        if (msg.length == 0) {
            return;
        }
        if (msg.length > maxMsgLen) {
            // TODO show error
            return;
        }
        // get master commitment
        let mcHex = DOM.sgm.mcHex.value;
        if (mcHex.length == 0) {
            return;
        }
        let mcBytes = hexToUint8Array(mcHex);
        // get skshares from UI
        let skshares = DOM.sgm.skshares.value.trim().split("\n").map(function(s) {
            let os = new OrderedShare()
            os.fromString(s);
            return os;
        });
        let sigshares = [];
        let sigsharesHex = "";
        for (let i=0; i<skshares.length; i++) {
            // create signature shares
            let skHex = skshares[i].shareHex;
            let shareIndex = skshares[i].shareIndex;
            let s = hexToUint8Array(skHex);
            let m = asciiToUint8Array(msg);
            let sigshareBytes = wasmHelpers.sign_msg(s, m);
            let sigshareHex = uint8ArrayToHex(sigshareBytes);
            let sigshare = new OrderedShare(shareIndex, sigshareHex);
            sigshares.push(sigshare);
            sigsharesHex += sigshare.toString() + "\n";
        }
        DOM.sgm.sigshares.value = sigsharesHex.trim();
        // combine signature shares
        let sig = wasmHelpers.combine_signatures(mcBytes, sigshares);
        let sigHex = uint8ArrayToHex(sig);
        DOM.sgm.sig.value = sigHex;
    }, 200);
}

})();
