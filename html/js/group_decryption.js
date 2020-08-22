(function() {

DOM.gd = document.querySelectorAll("#thresh-decryption")[0];
DOM.gd.skshares = DOM.gd.querySelectorAll(".skshares")[0];
DOM.gd.mcHex = DOM.gd.querySelectorAll(".mc-hex")[0];
DOM.gd.ct = DOM.gd.querySelectorAll(".ct")[0];
DOM.gd.msgshares = DOM.gd.querySelectorAll(".msg-shares")[0];
DOM.gd.msg = DOM.gd.querySelectorAll(".msg")[0];

DOM.gd.skshares.addEventListener("input", tryToDecrypt);
DOM.gd.mcHex.addEventListener("input", tryToDecrypt);
DOM.gd.ct.addEventListener("input", tryToDecrypt);

let gdDebounce = null;
function tryToDecrypt() {
    // if already using wasm buffers, try again later
    if (isWasming) {
        setTimeout(tryToDecrypt, 200);
        return;
    }
    // if typing is happening quickly wait until it stops.
    if (gdDebounce != null) {
        clearTimeout(gdDebounce);
    }
    gdDebounce = setTimeout(function() {
        // clear existing values
        DOM.gd.msgshares.value = "";
        DOM.gd.msg.value = "";
        // get ct from UI
        let ctHex = DOM.gd.ct.value;
        if (ctHex.length == 0) {
            return;
        }
        let ct = hexToUint8Array(ctHex);
        if (ct.length > maxCtLen) {
            // TODO show error
            return;
        }
        // get master commitment
        let mcHex = DOM.gd.mcHex.value;
        if (mcHex.length == 0) {
            return;
        }
        let mc = hexToUint8Array(mcHex);
        // set master commitment in wasm
        wasmHelpers.set_mc_bytes(mc);
        // get skshares from UI
        let skshares = DOM.gd.skshares.value.trim().split("\n").map(function(s) {
            let os = new OrderedShare()
            os.fromString(s);
            return os;
        });
        // check there are enough shares
        let threshold = wasmExports.get_mc_degree(mc.length);
        let m = threshold + 1;
        if (skshares.length < m) {
            // TODO show error
            console.log("Not enough shares");
            return;
        }
        // create decryption shares
        let msgshares = [];
        let msgsharesHex = "";
        for (let i=0; i<skshares.length; i++) {
            // create decryption shares
            let skHex = skshares[i].shareHex;
            let shareIndex = skshares[i].shareIndex;
            let s = hexToUint8Array(skHex);
            let dsBytes = wasmHelpers.create_decryption_share(s, i, shareIndex, ct);
            let dsHex = uint8ArrayToHex(dsBytes);
            let ds = new OrderedShare(shareIndex, dsHex);
            msgshares.push(ds);
            msgsharesHex += ds.toString() + "\n";
        }
        DOM.gd.msgshares.value = msgsharesHex.trim();
        // combine decryption shares
        let msgBytes = wasmHelpers.combine_decryption_shares(skshares.length, mc.length, ct.length);
        let msg = uint8ArrayToAscii(msgBytes);
        DOM.gd.msg.value = msg;
    }, 200);
}
})();
