// Copy and paste this into the dev console.

(function() {

let tests = [

    function() {
        let name = "Clicking generate shows sk and pk";
        DOM.skToPk.generate.dispatchEvent(clickEvt);
        let skLen = DOM.skToPk.skHex.value.length;
        if (skLen != 64) {
            throw(name + ": invalid sk length " + skLen);
        }
        let pkLen = DOM.skToPk.pkHex.value.length;
        if (pkLen != 96) {
            throw(name + ": invalid pk length " + pkLen);
        }
        next();
    },

    function() {
        let name = "Entering sk shows correct pk";
        DOM.skToPk.skHex.value = testData[0].sk;
        DOM.skToPk.skHex.dispatchEvent(inputEvt);
        let derivedPk = DOM.skToPk.pkHex.value;
        if (derivedPk != testData[0].pk) {
            throw(name + ": derived incorrect pk " + derivedPk);
        }
        next();
    },

    function() {
        let name = "Message can be signed with sk";
        DOM.signMsg.skHex.value = testData[0].sk;
        DOM.signMsg.msg.value = testData[0].msg;
        DOM.signMsg.msg.dispatchEvent(inputEvt);
        waitForChange(DOM.signMsg.sig, function() {
            let sig = DOM.signMsg.sig.value;
            if (sig != testData[0].sig) {
                throw(name + ": invalid signature " + sig);
            }
            next();
        });
    },

    function() {
        let name = "Signature can be verified";
        DOM.verify.pkHex.value = testData[0].pk;
        DOM.verify.msg.value = testData[0].msg;
        DOM.verify.sig.value = testData[0].sig;
        DOM.verify.sig.dispatchEvent(inputEvt);
        waitForChange(DOM.verify.valid, function() {
            let validity = DOM.verify.valid.value;
            if (validity != "valid") {
                throw(name + ": correct signature did not show as valid");
            }
            next();
        });
    },

    function() {
        let name = "Incorrect signature shows invalid";
        let invalidSig = testData[0].sig;
        invalidSig = "0000" + invalidSig.substring(4, invalidSig.length);
        DOM.verify.pkHex.value = testData[0].pk;
        DOM.verify.msg.value = testData[0].msg;
        DOM.verify.sig.value = invalidSig;
        DOM.verify.sig.dispatchEvent(inputEvt);
        waitForChange(DOM.verify.valid, function() {
            let validity = DOM.verify.valid.value;
            if (validity != "invalid") {
                throw(name + ": incorrect signature did not show as invalid");
            }
            next();
        });
    },

    function() {
        let name = "Message can be encrypted with pk";
        DOM.encrypt.pkHex.value = testData[0].pk;
        DOM.encrypt.msg.value = testData[0].msg;
        DOM.encrypt.msg.dispatchEvent(inputEvt);
        waitForChange(DOM.encrypt.ct, function() {
            let ct = DOM.encrypt.ct.value;
            // ct is different every time so cannot compare with testData
            if (ct.length == 0) {
                throw(name + ": no ciphertext generated");
            }
            next();
        });
    },

    function() {
        let name = "Ciphertext can be decrypted with sk";
        DOM.decrypt.skHex.value = testData[0].sk;
        DOM.decrypt.msg.value = testData[0].msg;
        DOM.decrypt.ct.value = testData[0].ct;
        DOM.decrypt.ct.dispatchEvent(inputEvt);
        waitForChange(DOM.decrypt.msg, function() {
            let msg = DOM.decrypt.msg.value;
            if (msg != testData[0].msg) {
                throw(name + ": incorrect decrypted message " + msg);
            }
            next();
        });
    },

    function() {
        let name = "Ciphertext cannot be decrypted with invalid sk";
        DOM.decrypt.skHex.value = testData[1].sk; // NB invalid sk
        DOM.decrypt.msg.value = testData[0].msg;
        DOM.decrypt.ct.value = testData[0].ct;
        DOM.decrypt.ct.dispatchEvent(inputEvt);
        waitForChange(DOM.decrypt.msg, function() {
            let msg = DOM.decrypt.msg.value;
            if (msg == testData[0].msg) {
                throw(name + ": decrypted ciphertext with invalid sk");
            }
            next();
        });
    },

    function() {
        let name = "Poly is converted to master keys and key sets";
        let d = testData[2];
        DOM.stk.polyHex.value = d.poly;
        DOM.stk.polyHex.dispatchEvent(inputEvt);
        if(DOM.stk.mskHex.value != d.msk) {
            throw(name + ": poly converted to incorrect master secret key");
        }
        if(DOM.stk.mpkHex.value != d.mpk) {
            throw(name + ": poly converted to incorrect master public key");
        }
        let secretKeys = DOM.stk.skset.value.split("\n");
        if (secretKeys.length != d.sks.length) {
            throw(name + ": expected " +  d.sks.length + " keys, got " + secretKeys.length);
        }
        for (let i=0; i<secretKeys.length; i++) {
            if (secretKeys[i] != d.sks[i]) {
                throw(name + " secret key " + i + " did not match");
            }
        }
        let publicKeys = DOM.stk.pkset.value.split("\n");
        if (publicKeys.length != d.pks.length) {
            throw(name + ": expected " +  d.pks.length + " keys, got " + publicKeys.length);
        }
        for (let i=0; i<publicKeys.length; i++) {
            if (publicKeys[i] != d.pks[i]) {
                throw(name + " public key " + i + " did not match");
            }
        }
        next();
    },

    function() {
        let name = "Poly can be randomly generated";
        DOM.stk.generate.dispatchEvent(clickEvt);
        if (DOM.stk.polyHex.value.length == 0) {
            throw(name + ": poly length zero when clicking generate");
        }
        if (DOM.stk.mskHex.value.length == 0) {
            throw(name + ": master secret key length zero when clicking generate");
        }
        if (DOM.stk.mpkHex.value.length == 0) {
            throw(name + ": master public key length zero when clicking generate");
        }
        if (DOM.stk.skset.value.length == 0) {
            throw(name + ": secret key set length zero when clicking generate");
        }
        if (DOM.stk.pkset.value.length == 0) {
            throw(name + ": public key set length zero when clicking generate");
        }
        next();
    },

    function() {
        let name = "DKG can be generated";
        DOM.dkg.generate.dispatchEvent(clickEvt);
        if (DOM.dkg.mpkHex.value.length == 0) {
            throw(name + ": dkg mpk length zero when clicking generate");
        }
        if (DOM.dkg.shareCreation.value.length == 0) {
            throw(name + ": dkg share creation length zero when clicking generate");
        }
        if (DOM.dkg.sharesCreated.textContent.trim().length == 0) {
            throw(name + ": dkg shares created length zero when clicking generate");
        }
        if (DOM.dkg.sharesReceived.textContent.trim().length == 0) {
            throw(name + ": dkg shares received length zero when clicking generate");
        }
        if (DOM.dkg.skshareHex.value.length == 0) {
            throw(name + ": dkg skshare length zero when clicking generate");
        }
        if (DOM.dkg.allSkshares.value.length == 0) {
            throw(name + ": dkg all skshares length zero when clicking generate");
        }
        if (DOM.dkg.allShareCreations.value.length == 0) {
            throw(name + ": dkg all share creations length zero when clicking generate");
        }
        if (DOM.dkg.mskPolyHex.value.length == 0) {
            throw(name + ": dkg msk poly length zero when clicking generate");
        }
        next();
    },

    // TODO less urgent tests:
    // Changing threshold changes poly
    // Changing total-keys shows correct number of keys
    // Cannot set n to be less than m
    // Cannot set m to be more than n
    // m cannot be less than 2
    // m cannot be more than 10
    // n cannot be less than 2
    // n cannot be more than 10
    // master secret key can be used in ui derive public key from secret key

];

let clickEvt = new Event("click");
let inputEvt = new Event("input");

let testData = [
    {
        // sk and pk are generated by safe-api command
        // safe auth create-acc
        sk: "4565f46155ec5b511349793af4fb82260d8d35c867620afd88a220ad4430ae00",
        pk: "828f992ddd9d7bbc96bb412badae70cbda0fabebd5d722230965a49c41d50d3b1b372f6351291b7d34a2bb54920c35a1",
        msg: "test message",
        sig: "813a32ea040a5437058d5becea3e6c1a1f1cf41878210ee572ad2ef12f6008e42b4e9b80955e491f022f2eac52b93ccd0491ba85dea89a010e18f73a2a868bace8fe871702160b65560e8a3e3c4f72a25e8b1a6a364770e99aeb88f121485fe3",
        ct: "945c519abf706abc9b74fd1ad5f71d932a511195f9399946abad10b4616733b5fc8e21fc0d2573487e34ca4595ecccf10c000000000000007abdeffe50549fe60cde07d198a884563fc6dd535be9cf44616443678657a4c8e07e1d972966968087c14c99a658d1e5ead0c866aa32938cac6ecfd9166c28afc94018742e58d3d394a636a191f72f98b0674ec9f88b2b369d8c74bfeb5b67a600b84be8c650b0181ceeff28"
    },
    {
        "sk": "8c4a86586c9a4efdf713a67aa78ea31a2adc060f99307a21cd17029e50cb6422",
    },
    {
        // generated from threshold_crypto test
        // https://github.com/poanetwork/threshold_crypto/blob/7709462f2df487ada3bb3243060504b5881f2628/src/lib.rs#L823
        "poly": "04000000000000008f142a30152b6830f6a1cdd0dc41894b84f07a9ae26d74492c74539521a5455ba9daecbc962c91cf99b09c16876921538c8ad3dfe1da01295ea1e4fb93ea6f3281aeb52ce7b67895be84d1ad8b538a063d93f23d2527f1d9ad988c9ebdf24e07a7b1dd479ebf3eb04f6354f87e2cc718490a03d95686147de4af77d10fc2744a",
        "threshold": 3,
        "msk": "8f142a30152b6830f6a1cdd0dc41894b84f07a9ae26d74492c74539521a5455b",
        "mpk": "9727732a79858e28f06303129e589bf7b7c5e54070e500e122dd895afb67091c9c53750f933c4d0b14d8d28626f96031",
        "sks": [
            "0:5f4faa6132ceb0459fde918d6b873e6a9140a287381e4296d4e09ed72f9d8b6b",
            "1:1611c89bd85c63a7a8acfb77fc4aff87b4bc97d6b90a4c85ca2bbe6f78c28705",
            "2:9c83b58dbf54f876f2a70862834ffb9199f2298a5fa9999ed87944f3b3521b00",
            "3:d7d0a4e6a033e8d55eb4b91dee0fe7cde1bfe39112c0be0339f589a4f43c4c4a",
            "4:ac22c8553777abe5d059117d2763b92d292aaed3b33c15a3dd4a499cf9c8325f",
            "5:01a3518a3c9dbac72a7c10521dc426f7100f143f2ce5309e00a5da1cd5e5d42d",
            "6:bd7b733369238e9d4d5bb66ec051a1c33f2442cd6c57df4924ab3392ec292619",
        ],
        "pks": [
            "0:8d4768421ae667f4b9d2682043b5ed2d558f579a0760f5a914ee29e5eb1f242cda5ae2a94d3458ef8812656abab3aeae",
            "1:a4943326e90bc64046c802072267388906e7bdddd4945e507cc6b7d9371c53689ddaa1cf9fabc15654facf10cdcbff4c",
            "2:a7d380921170560295827a732d262333f621d76e0f27ba35dfb2eabcb3f74f36236a82283e42b8377ceb915974dc0abb",
            "3:89387fac31f4d852381b55a8af11db64efb788e0de29c26cb1e08c88c3d2016ab446af5c196fe52f848745a45ea18517",
            "4:86090d8dc19d88f0621adf1d97ddcc873ad49296d741b10cb8370b31d5cff0334190b1eeb4873faff61fbdad7802ef92",
            "5:ac9bc16eb85402eadcd65110e4e6837c46a60d386e085a68eef4c093314ddb19195099f9f3067beecf2b9404122975b6",
            "6:85c747db393bbe62f0182e2c65aad184b6836bbd7bac1548c892a0ac4181b31fd899c2d5eb07d0a94739d9bd61ef6145",
        ],
    },
];

let initialValue = null;
let retries = 0;
function waitForChange(el, fn) {
    if (initialValue == null) {
        initialValue = el.value;
    }
    let valueHasChanged = el.value != initialValue;
    if (valueHasChanged || retries > 10) {
        initialValue = null;
        retries = 0;
        fn();
    }
    else {
        retries += 1;
        setTimeout(function() { waitForChange(el, fn) }, 100);
    }
}

function shuffle(a) {
    for (let i = a.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
}

let testIndex = -1;
function next() {
    testIndex += 1;
    if (testIndex >= tests.length) {
        console.log("All tests passed");
        return;
    }
    console.log("Running test " + (testIndex + 1) + " of " + tests.length);
    tests[testIndex]();
}

tests = shuffle(tests);
next();

})();
