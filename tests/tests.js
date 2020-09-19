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
        if (DOM.dkg.allPkshares.value.length == 0) {
            throw(name + ": dkg all pkshares length zero when clicking generate");
        }
        if (DOM.dkg.allShareCreations.value.length == 0) {
            throw(name + ": dkg all share creations length zero when clicking generate");
        }
        if (DOM.dkg.mskPolyHex.value.length == 0) {
            throw(name + ": dkg msk poly length zero when clicking generate");
        }
        next();
    },

    function() {
        let name = "Group signature can be created";
        // m is 4
        let skshares = [
            testData[2].sks[0],
            testData[2].sks[1],
            testData[2].sks[2],
            testData[2].sks[3],
        ];
        DOM.sgm.skshares.value = skshares.join("\n");
        DOM.sgm.mcHex.value = testData[2].mc;
        DOM.sgm.msg.value = testData[2].msg;
        DOM.sgm.msg.dispatchEvent(inputEvt);
        // check sigshares are shown
        waitForChange(DOM.sgm.sigshares, function() {
            let sigshares = DOM.sgm.sigshares.value.split("\n");
            if (sigshares.length != skshares.length) {
                throw(name + ": different number of sigshares to skshares");
            }
            for (let i=0; i<sigshares.length; i++) {
                if (sigshares[i] != testData[2].sigshares[i]) {
                    throw(name + ": incorrect sigshare " + i);
                }
            }
            // check group signature is shown
            let sig = DOM.sgm.sig.value;
            if (sig != testData[2].sig) {
                throw(name + ": incorrect signature");
            }
            // check group signature is valid
            DOM.verify.pkHex.value = testData[2].mpk;
            DOM.verify.msg.value = testData[2].msg;
            DOM.verify.sig.value = sig;
            DOM.verify.sig.dispatchEvent(inputEvt);
            waitForChange(DOM.verify.valid, function() {
                let validity = DOM.verify.valid.value;
                if (validity != "valid") {
                    throw(name + ": group signature did not show as valid");
                }
                next();
            });
        });
    },

    function() {
        let name = "Group encrypted message can be decrypted";
        // m is 4
        let skshares = [
            testData[2].sks[0],
            testData[2].sks[1],
            testData[2].sks[2],
            testData[2].sks[3],
        ];
        DOM.gd.skshares.value = skshares.join("\n");
        DOM.gd.mcHex.value = testData[2].mc;
        DOM.gd.ct.value = testData[2].ct;
        DOM.gd.ct.dispatchEvent(inputEvt);
        // check decryption shares are shown
        waitForChange(DOM.gd.msgshares, function() {
            let msgshares = DOM.gd.msgshares.value.split("\n");
            if (msgshares.length != skshares.length) {
                throw(name + ": incorret number of decryption shares");
            }
            for (let i=0; i<msgshares.length; i++) {
                if (msgshares[i] != testData[2].decryption_shares[i]) {
                    throw(name + ": incorrect decryption share " + i);
                }
            }
            // check group plaintext is shown
            let msg = DOM.gd.msg.value;
            if (msg != testData[2].msg) {
                throw(name + ": incorrect plaintext");
            }
            next();
        });
    },

    function() {
        let name = "Simple Threshold Keys sets m when poly is set";
        // set poly where m is 4
        let d = testData[2];
        DOM.stk.polyHex.value = d.poly;
        DOM.stk.polyHex.dispatchEvent(inputEvt);
        // check m is shown as 4
        let m = DOM.stk.m.value;
        if (m != 4) {
            throw(name + ": m is not 4");
        }
        // change to poly where m is 3
        d = testData[3];
        DOM.stk.polyHex.value = d.poly;
        DOM.stk.polyHex.dispatchEvent(inputEvt);
        // check m is shown as 3
        m = DOM.stk.m.value;
        if (m != 3) {
            throw(name + ": m did not change to 3");
        }
        next();
    },

    function() {
        let name = "Simple Threshold Keys can vary the total keys shown";
        let keysToShow = 20;
        // set poly to derive keys from
        let d = testData[2];
        DOM.stk.polyHex.value = d.poly;
        // set number of keys to show
        DOM.stk.totalKeys.value = keysToShow;
        DOM.stk.totalKeys.dispatchEvent(inputEvt);
        // check correct number of keys are shown
        waitForChange(DOM.stk.skset, function() {
            let sks = DOM.stk.skset.value.split("\n");
            if (sks.length != keysToShow) {
                throw(name + ": incorrect number of keys shown");
            }
            next();
        });
    },

    // TODO less urgent tests:
    // STK and DKG Cannot set n to be less than m
    // STK and DKG Cannot set m to be more than n
    // STK and DKG m cannot be less than 2
    // STK and DKG m cannot be more than 10
    // STK and DKG n cannot be less than 2
    // STK and DKG n cannot be more than 10
    // STK and DKG master secret key can be used in ui derive public key from secret key
    // STK check master commitment value is correct
    // DKG secret key shares can be used to derive public key shares
    // DKG master secret key poly can be used to derive secret key share set
    // DKG changing number of nodes shows correct number of nodes
    // SGM and GD Choice of m shares can be arbitrary
    // SGM and GD Order of shares can be arbitrary
    // SGM and GD Signature/message is same for any combo of m shares
    // SGM and GD Can enter more than m shares
    // SGM and GD Less than m shares shows error
    // SGM and GD Using share not derived from poly does not verify/decrypt
    // SGM and GD Master Commitment not derived from poly does not verify/decrypt
    // SGM and GD Incorrect share index does not verify/decrypt
    // GD Incorrect ciphertext shows error

];

let clickEvt = new Event("click");
let inputEvt = new Event("input");

let testData = [
    { // testData[0]
        // sk and pk are generated by safe-api command
        // safe auth create-acc
        sk: "4565f46155ec5b511349793af4fb82260d8d35c867620afd88a220ad4430ae00",
        pk: "828f992ddd9d7bbc96bb412badae70cbda0fabebd5d722230965a49c41d50d3b1b372f6351291b7d34a2bb54920c35a1",
        msg: "test message",
        sig: "813a32ea040a5437058d5becea3e6c1a1f1cf41878210ee572ad2ef12f6008e42b4e9b80955e491f022f2eac52b93ccd0491ba85dea89a010e18f73a2a868bace8fe871702160b65560e8a3e3c4f72a25e8b1a6a364770e99aeb88f121485fe3",
        ct: "945c519abf706abc9b74fd1ad5f71d932a511195f9399946abad10b4616733b5fc8e21fc0d2573487e34ca4595ecccf10c000000000000007abdeffe50549fe60cde07d198a884563fc6dd535be9cf44616443678657a4c8e07e1d972966968087c14c99a658d1e5ead0c866aa32938cac6ecfd9166c28afc94018742e58d3d394a636a191f72f98b0674ec9f88b2b369d8c74bfeb5b67a600b84be8c650b0181ceeff28"
    },
    { // testData[1]
        "sk": "8c4a86586c9a4efdf713a67aa78ea31a2adc060f99307a21cd17029e50cb6422",
    },
    { // testData[2]
        // generated from threshold_crypto test
        // https://github.com/poanetwork/threshold_crypto/blob/7709462f2df487ada3bb3243060504b5881f2628/src/lib.rs#L823
        "poly": "04000000000000008f142a30152b6830f6a1cdd0dc41894b84f07a9ae26d74492c74539521a5455ba9daecbc962c91cf99b09c16876921538c8ad3dfe1da01295ea1e4fb93ea6f3281aeb52ce7b67895be84d1ad8b538a063d93f23d2527f1d9ad988c9ebdf24e07a7b1dd479ebf3eb04f6354f87e2cc718490a03d95686147de4af77d10fc2744a",
        "threshold": 3,
        "m": 4,
        "msk": "8f142a30152b6830f6a1cdd0dc41894b84f07a9ae26d74492c74539521a5455b",
        "mpk": "9727732a79858e28f06303129e589bf7b7c5e54070e500e122dd895afb67091c9c53750f933c4d0b14d8d28626f96031",
        "mc": "04000000000000009727732a79858e28f06303129e589bf7b7c5e54070e500e122dd895afb67091c9c53750f933c4d0b14d8d28626f96031990d99e114bff59020b7e66e076148a4c27807b255ff98e988c5ab0d6d37033b9157066e87ea50d1e7b4068a8b4b5234960b6c2684ce5fb3efffa9dcb0a226148b1d6a3c20fb936a1e71aaf44a8c39924f51fc5df7ba7c6b687b4f5ebc884ddbb838a3c58abe3d9165d91deed6cf6358f18824c06f5e6f0aae972910f20cead6c2c3cbc2b78b25106c336a0cc497f8c8",
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
        "msg": "test message",
        "sigshares": [
            "0:b3fb008f41425b6a6fe0b3dc24a8dcac3bab717f049366d3e01ffcc0a6f79246576d3bdd6b8b4861021fe2a913b3e4bb1135d751c4b2687660cbc17902c09b153a38679e6f0841fa0ebf8c27667793e892bb622d1f0ded742c09f49a9f33ca21",
            "1:b699d2bd8488709f2a781ef7215d0d3f527c8bf469998d3b35cdc295fcfdb952e5304477ca3874a742a24c91f70c33d20f9aa749af3cfd2f81ac2d26866d0f0f7770e67159e1ad7b7c38a8d5e7489d86472687a4707a2294843b948ad423e838",
            "2:af75c0910118d70ab789ed4d4456361f0bc34985d53995d2997e02366f25e0ebeb54b97f20e9043a54a06a0baa7bbf0807ede317061a3c3bf688b4ed482c4dcb6bd4bdcf282d5f23e1454114f734a3c4c88f4855cb5ccfc31621a1a637d17baf",
            "3:8a78d1367ec7051dac1e06a1eba8e88056ed67e1da32e6d2117fbaf93ba211980241b77ea992e64d6fa7fdeb5099587b17b84d3d5bfbeb74a312aba2690d31b9a089ab54e5688b551f69eefca67d783d614d495e8ec1ae5dd5872032525cec7b",
            "4:8adc1c4adab8699fb0669229beda628d93d7965463be34f51b9fccfe0062f69e3d1b69ff7da62cd87e72d1b9618dc61e113ea007c3809d0a88e490b170f9a8136716eb6c31993c260e0f0e5cf7574869501253a981fe9bc3426330081f8373af",
            "5:b8a66e74f6876f4ce832f00c522410b5193799530ad343eb70b46bf2fd87815fc677adaab76fd1b8a40f8c8c86ba5c5205cd3653cbf65cd020d43e760018f90f1666c46a9aae8ccb783e8600571da1ac191ca519da02374d782ca28468da0078",
            "6:9695042df154e73274f2e754aab6a99f78023a4bbdde51ad949244bee72530ccd5c4aa9194bbb469ff4bdfd20197e56913bf4a7c644d9cae34009deee5e6336970b0482750ccb9f1db3ad19330a34a0dc93442d37cbca9ca5cccc7a09482e301",
        ],
        "sig": "b166a36dcd7a6b7a9b6b47faed22dec916dc9a105090cdd66c5740df1695ccedb26afdc6ac07467fcecb44a8da57d52400c9efeb4b0dbc01a252c09df4b49dc700a0a8085282abda489353ce64e45d48c1508f431499f56a66d673805e8f7f6b",
        "ct": "b7710133e37845b4c8037700a7b6ed8821a3e1a13b44126cde3492ae72ff14af080e74e6f52d413bd8c78588cffae1df0c000000000000008b04c5cca27c5d915e96073ba2fe08f0e5da38160d249ff879deb7f07e1de226fc734b6c87c407e1f6162edfcb7d168ea2de71e4ffeef5e5b79643fb0cd0856fe7cdb4fd512379527b1e5929460474d9f57acac2ac46aab0690620373bb014b816d959c26d7b77d4bec4dfd3",
        "decryption_shares": [
            "0:a6bb1e47100241900621a2dbb4e7beedfe0ce64719d49e1b4ab72e588a18b5eeed20ef17997df502e4d1201e8b00e541",
            "1:b99f13a73f968d189adc1ab67653c13e4b9499b8f6e1923be30d50826a9a578aa508d2b2ca02af227f9e5d45c6c14df4",
            "2:8ce93d76eb295ca8abb6c2bda84766d2a6472ec746ce2bf800d5a77c64736503c3c8decb3bf436b2fdace652a7d01772",
            "3:aa8f9e80f66d8aed1d686b64b1369b80d0cf8c8c5b614983658934a36a39b91c7756de56f273ea0e8bf438421e443cef",
            "4:850905cfbd7aa80c30a1b5dcf794bafc0b5dcbf3edb48700d45b374aee7420dc3ba14bea1e3f7d3415431b65a50a1ef3",
            "5:98e1002b548aafcc37f8dd6192864b29fa047695ee8dae5446195029b28c36c55ce654521d98d88fd7b72b59cfc6587f",
            "6:a859928516ccfcc85668358e27d16e22fc3258e99abd35d21f95fa2ef8c3de49917c19c4a9f49e461f5b0f2c4a99821d",
        ],
    },
    { // testData[3]
        "poly": "030000000000000062376fe564a4ab2a828010c83ce3edeaecac5928fa9d4ca1ac8b2dae7ddf3a4dbd345bdc85ee04e9786b6ead9670a8caaeab4170c637322d1ea1626acb2a0843b6f70b7753eb6745bec73e268cfc8b93b508f84d6d40cafb76d239fb09797c6e",
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

function resetUi() {
    for (root in DOM) {
        for (elName in DOM[root]) {
            let el = DOM[root][elName];
            if ("value" in el) {
                let key = root + elName;
                DOM[root][elName].value = initialElValues[key];
            }
        }
    }
}

let initialElValues = {};
function setInitialElValues() {
    for (root in DOM) {
        for (elName in DOM[root]) {
            let el = DOM[root][elName];
            if ("value" in el) {
                let key = root + elName;
                initialElValues[key] = DOM[root][elName].value;
            }
        }
    }
}

let testIndex = -1;
function next() {
    testIndex += 1;
    if (testIndex >= tests.length) {
        console.log("All tests passed");
        return;
    }
    console.log("Running test " + (testIndex + 1) + " of " + tests.length);
    resetUi();
    tests[testIndex]();
}

setInitialElValues();
tests = shuffle(tests);
next();

})();
