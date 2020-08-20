(function() {

DOM.stk = {}; // simple threshold keys
DOM.stk.generate = document.querySelectorAll("#simple-threshold-keys .generate")[0];
DOM.stk.m = document.querySelectorAll("#simple-threshold-keys .m")[0];
DOM.stk.polyHex = document.querySelectorAll("#simple-threshold-keys .poly-hex")[0];
DOM.stk.mskHex = document.querySelectorAll("#simple-threshold-keys .msk-hex")[0];
DOM.stk.mpkHex = document.querySelectorAll("#simple-threshold-keys .mpk-hex")[0];
DOM.stk.totalKeys = document.querySelectorAll("#simple-threshold-keys .total-keys")[0];
DOM.stk.skset = document.querySelectorAll("#simple-threshold-keys .skset")[0];
DOM.stk.pkset = document.querySelectorAll("#simple-threshold-keys .pkset")[0];

DOM.stk.generate.addEventListener("click", generatePoly);
DOM.stk.polyHex.addEventListener("input", deriveStk);
DOM.stk.totalKeys.addEventListener("input", deriveStk);

function generatePoly() {
    let m = parseInt(DOM.stk.m.value);
    let threshold = m - 1;
    let polyBytes = wasmHelpers.generate_poly(threshold);
    let polyHex = uint8ArrayToHex(polyBytes);
    DOM.stk.polyHex.value = polyHex;
    deriveStk();
}

function deriveStk() {
    // set poly in wasm
    let polyHex = DOM.stk.polyHex.value;
    let polyBytes = hexToUint8Array(polyHex);
    for (let i=0; i<polyBytes.length; i++) {
        let v = polyBytes[i];
        wasmExports.set_poly_byte(i, v);
    }
    // get threshold
    let threshold = wasmExports.get_poly_degree();
    DOM.stk.m.value = threshold + 1;
    // derive master keys, ie index 0
    let mkIndex = 0;
    wasmExports.derive_master_key();
    // show master secret key
    let mskBytes = wasmHelpers.get_msk_bytes();
    let mskHex = uint8ArrayToHex(mskBytes);
    DOM.stk.mskHex.value = mskHex;
    // show master public key
    let mpkBytes = wasmHelpers.get_mpk_bytes();
    let mpkHex = uint8ArrayToHex(mpkBytes);
    DOM.stk.mpkHex.value = mpkHex;
    // derive keys, ie index 1 to N
    let n = parseInt(DOM.stk.totalKeys.value);
    let skshares = "";
    let pkshares = "";
    for (let i=0; i<n; i++) {
        wasmExports.derive_key_share(i);
        let skshareBytes = wasmHelpers.get_skshare();
        let skshareHex = uint8ArrayToHex(skshareBytes);
        skshares += skshareHex + "\n";
        // show master public key
        let pkshareBytes = wasmHelpers.get_pkshare();
        let pkshareHex = uint8ArrayToHex(pkshareBytes);
        pkshares += pkshareHex + "\n";
    }
    DOM.stk.skset.value = skshares.trim();
    DOM.stk.pkset.value = pkshares.trim();
}

})();
