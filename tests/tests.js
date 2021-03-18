// Copy and paste this into the dev console.

(function() {

let tests = [

    function() {
        let name = "Clicking generate shows sk and pk";
        DOM.skToPk.generate.dispatchEvent(clickEvt);
        let skLen = DOM.skToPk.sk.value.length;
        if (skLen != 64) {
            throw(name + ": invalid sk length " + skLen);
        }
        let pkLen = DOM.skToPk.pk.value.length;
        if (pkLen != 96) {
            throw(name + ": invalid pk length " + pkLen);
        }
        next();
    },

    function() {
        let name = "Entering sk shows correct pk";
        DOM.skToPk.sk.value = testData[0].sk;
        DOM.skToPk.sk.dispatchEvent(inputEvt);
        let derivedPk = DOM.skToPk.pk.value;
        if (derivedPk != testData[0].pk) {
            throw(name + ": derived incorrect pk " + derivedPk);
        }
        next();
    },

    function() {
        // Chia.net is the only place I could find test vectors that
        // have hex encoded bls12-381 secret and public keys.
        // There are many places that specify big endian but not many
        // that have tests for it.
        // For more info see
        // https://safenetforum.org/t/simple-web-based-tool-for-bls-keys/32339/36
        let name = "is cross compatible with other bls libraries";
        DOM.skToPk.sk.value = testData[4].sk;
        DOM.skToPk.sk.dispatchEvent(inputEvt);
        let derivedPk = DOM.skToPk.pk.value;
        if (derivedPk != testData[4].pk) {
            throw(name + ": derived incorrect pk " + derivedPk);
        }
        // signature check
        // TODO currently does not pass, see
        // https://github.com/poanetwork/threshold_crypto/issues/110
        /*
        DOM.verify.pk.value = testData[4].pk;
        DOM.verify.msg.value = testData[4].msg;
        DOM.verify.sig.value = testData[4].sig;
        DOM.verify.sig.dispatchEvent(inputEvt);
        waitForChange(DOM.verify.valid, function() {
            let validity = DOM.verify.valid.value;
            if (validity != "valid") {
                throw(name + ": chia signature did not show as valid");
            }
            next();
        });
        */
        next();
    },

    function() {
        let name = "Message can be signed with sk";
        DOM.signMsg.sk.value = testData[0].sk;
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
        DOM.verify.pk.value = testData[0].pk;
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
        DOM.verify.pk.value = testData[0].pk;
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
        DOM.encrypt.pk.value = testData[0].pk;
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
        DOM.decrypt.sk.value = testData[0].sk;
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
        DOM.decrypt.sk.value = testData[1].sk; // NB invalid sk
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
            DOM.verify.pk.value = testData[2].mpk;
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
        // sk and pk are generated by this tool, since sn_api does not currently show keys
        sk: "00ae3044ad20a288fd0a6267c8358d0d2682fbf43a794913515bec5561f46545",
        pk: "828f992ddd9d7bbc96bb412badae70cbda0fabebd5d722230965a49c41d50d3b1b372f6351291b7d34a2bb54920c35a1",
        msg: "test message",
        sig: "813a32ea040a5437058d5becea3e6c1a1f1cf41878210ee572ad2ef12f6008e42b4e9b80955e491f022f2eac52b93ccd0491ba85dea89a010e18f73a2a868bace8fe871702160b65560e8a3e3c4f72a25e8b1a6a364770e99aeb88f121485fe3",
        ct: "28ffee1c18b050c6e84bb800a6675bebbf748c9d362b8bf8c94e67b0982ff791a136a694d3d3582e741840c9af286c16d9cf6eac8c9332aa66c8d0eae5d158a6994cc18780966629971d7ee0c8a457866743646144cfe95b53ddc63f5684a898d107de0ce69f5450feefbd7a000000000000000cf1ccec9545ca347e4873250dfc218efcb5336761b410adab469939f99511512a931df7d51afd749bbc6a70bf9a515c94"
    },
    { // testData[1]
        "sk": "2264cb509e0217cd217a30990f06dc2a1aa38ea77aa613f7fd4e9a6c58864a8c",
    },
    { // testData[2]
        // generated from threshold_crypto test
        // https://github.com/poanetwork/threshold_crypto/blob/7709462f2df487ada3bb3243060504b5881f2628/src/lib.rs#L823
        "poly": "4a74c20fd177afe47d148656d9030a4918c72c7ef854634fb03ebf9e47ddb1a7074ef2bd9e8c98add9f127253df2933d068a538badd184be9578b6e72cb5ae81326fea93fbe4a15e2901dae1dfd38a8c53216987169cb099cf912c96bcecdaa95b45a5219553742c49746de29a7af0844b8941dcd0cda1f630682b15302a148f0000000000000004",
        "threshold": 3,
        "m": 4,
        "msk": "5b45a5219553742c49746de29a7af0844b8941dcd0cda1f630682b15302a148f",
        "mpk": "9727732a79858e28f06303129e589bf7b7c5e54070e500e122dd895afb67091c9c53750f933c4d0b14d8d28626f96031",
        "mc": "c8f897c40c6a336c10258bb7c2cbc3c2d6ea0cf2102997ae0a6f5e6fc02488f15863cfd6ee1dd965913dbe8ac5a338b8db4d88bc5e4f7b686b7cbaf75dfc514f92398c4af4aa711e6a93fb203c6a1d8b1426a2b0dca9ffefb35fce84266c0b9634524b8b8a06b4e7d150ea876e0657913b03376d0dabc588e998ff55b20778c2a44861076ee6b72090f5bf14e1990d993160f92686d2d8140b4d3c930f75539c1c0967fb5a89dd22e100e57040e5c5b7f79b589e120363f0288e85792a7327970000000000000004",
        "sks": [
            "0:6b8b9d2fd79ee0d496421e3887a240916a3e876b8d91de9f45b0ce3261aa4f5f",
            "1:0587c2786fbe2bca854c0ab9d697bcb487ff4afc77fbaca8a7635cd89bc81116",
            "2:001b52b3f34479d89e99a95f8a29f29991fb4f836208a7f276f854bf8db5839c",
            "3:4a4c3cf4a489f53903bec01291e3bfe1cde70fee1db9b45ed5e833a0e6a4d0d7",
            "4:5f32c8f99c494adda3153cb3d3ae2a292db963277d1159d0e5ab773755c822ac",
            "5:2dd4e5d51cdaa5009e30e52c3f140f10f726c41d52107c2ac7ba9d3c8a51a301",
            "6:192629ec9233ab2449df576ccd42243fc3a151c06eb65b4d9d8e236933737bbd",
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
        "ct": "d3dfc4bed4777b6dc259d916b814b03b37200669b0aa46acc2ca7af5d974044629591e7b52792351fdb4cde76f85d00cfb4396b7e5f5eeffe471dea28e167dcbdf2e16f6e107c4876c4b73fc26e21d7ef0b7de79f89f240d1638dae5f008fea23b07965e915d7ca2ccc5048b000000000000000cdfe1facf8885c7d83b412df5e6740e08af14ff72ae9234de6c12443ba1e1a32188edb6a7007703c8b44578e3330171b7",
        "decryption_shares": [
            "0:41e5008b1e20d1e402f57d9917ef20edeeb5188a582eb74a1b9ed41947e60cfeedbee7b4dba2210690410210471ebba6",
            "1:f44dc1c6455d9e7f22af02cab2d208a58a579a6a82500de33b92e1f6b899944b3ec15376b61adc9a188d963fa7139fb9",
            "2:7217d0a752e6acfdb236f43bcbdec8c3036573647ca7d500f82bce46c72e47a6d26647a8bdc2b6aba85c29eb763de98c",
            "3:ef3c441e4238f48b0eea73f256de56771cb9396aa33489658349615b8c8ccfd0809b36b1646b681ded8a6df6809e8faa",
            "4:f31e0aa5651b4315347d3f1eea4ba13bdc2074ee4a375bd40087b4edf3cb5d0bfcba94f7dcb5a1300ca87abdcf050985",
            "5:7f58c6cf592bb7d78fd8981d5254e65cc5368cb22950194654ae8dee957604fa294b869261ddf837ccaf8a542b00e198",
            "6:1d82994a2c0f5b1f469ef4a9c4197c9149dec3f82efa951fd235bd9ae95832fc226ed1278e356856c8fccc16859259a8",
        ],
    },
    { // testData[3]
        "poly": "6e7c7909fb39d276fbca406d4df808b5938bfc8c263ec7be4567eb53770bf7b643082acb6a62a11e2d3237c67041abaecaa87096ad6e6b78e904ee85dc5b34bd4d3adf7dae2d8baca14c9dfa2859aceceaede33cc81080822aaba464e56f37620000000000000003",
    },
    { // testData[4]
        // sk and pk are from https://github.com/Chia-Network/bls-signatures/blob/ee71adc0efeae3a7487cf0662b7bee3825752a29/src/test.cpp#L254-L260
        sk: "4a353be3dac091a0a7e640620372f5e1e2e4401717c1e79cac6ffba8f6905604",
        pk: "85695fcbc06cc4c4c9451f4dce21cbf8de3e5a13bf48f44cdbb18e2038ba7b8bb1632d7911ef1e2e08749bddbf165352",
        sig: "b8faa6d6a3881c9fdbad803b170d70ca5cbf1e6ba5a586262df368c75acd1d1ffa3ab6ee21c71f844494659878f5eb230c958dd576b08b8564aad2ee0992e85a1e565f299cd53a285de729937f70dc176a1f01432129bb2b94d3d5031f8065a1",
        msg: String.fromCharCode(7)+String.fromCharCode(8)+String.fromCharCode(9),
    }
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
