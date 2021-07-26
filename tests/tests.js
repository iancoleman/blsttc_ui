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
        sk: "00ae3044ad20a288fd0a6267c8358d0d2682fbf43a794913515bec5561f46545",
        pk: "828f992ddd9d7bbc96bb412badae70cbda0fabebd5d722230965a49c41d50d3b1b372f6351291b7d34a2bb54920c35a1",
        msg: "test message",
        sig: "938133dd444b8edc07a44ad53cea1c168c9c820384b175cbe138c9175aa550d88a98b7e101c620389301ff6de60e044419b8de6757ab03d7a3f6348729fa962c6b2dc36e6a49fae474b018f0f356c60f527f9be75f343d68c2cd18d074c0f144",
        ct: "b1e4abbeb6633b05ecb3c873c4d5a050b3c4bb324450f2ec201f6dfc1a546873bde076659641d4d8808d503bc93c3b1ba0f1fe61ef90cae43bd669ba761e5a8afdb72b629233d4ce09a45cb9a03e1756010fd14da6d095ba97b4c76d276030f40f891ca829e2adfac70c94b1768149be7696c99e5969327e66b5abe4faf26bbc0b2f2dfc47646de3afd4c76e61f96e6b154c906308cc22ac5c7ba5b4"
    },
    { // testData[1]
        "sk": "2264cb509e0217cd217a30990f06dc2a1aa38ea77aa613f7fd4e9a6c58864a8c",
    },
    { // testData[2]
        "poly": "4a74c20fd177afe47d148656d9030a4918c72c7ef854634fb03ebf9e47ddb1a7074ef2bd9e8c98add9f127253df2933d068a538badd184be9578b6e72cb5ae81326fea93fbe4a15e2901dae1dfd38a8c53216987169cb099cf912c96bcecdaa95b45a5219553742c49746de29a7af0844b8941dcd0cda1f630682b15302a148f",
        "threshold": 3,
        "m": 4,
        "msk": "4a74c20fd177afe47d148656d9030a4918c72c7ef854634fb03ebf9e47ddb1a7",
        "mpk": "b838a3c58abe3d9165d91deed6cf6358f18824c06f5e6f0aae972910f20cead6c2c3cbc2b78b25106c336a0cc497f8c8",
        "mc": "b838a3c58abe3d9165d91deed6cf6358f18824c06f5e6f0aae972910f20cead6c2c3cbc2b78b25106c336a0cc497f8c8960b6c2684ce5fb3efffa9dcb0a226148b1d6a3c20fb936a1e71aaf44a8c39924f51fc5df7ba7c6b687b4f5ebc884ddb990d99e114bff59020b7e66e076148a4c27807b255ff98e988c5ab0d6d37033b9157066e87ea50d1e7b4068a8b4b52349727732a79858e28f06303129e589bf7b7c5e54070e500e122dd895afb67091c9c53750f933c4d0b14d8d28626f96031",
        "sks": [
            "0:6b8b9d2fd79ee0d496421e3887a240916a3e876b8d91de9f45b0ce3261aa4f5f",
            "1:5d92404e5bd31dd986d2eefd5aff1eec30be688134e45eed9cb63879164d1dbd",
            "2:008645950df5ad94076053ccc1d210588eca26ddd325e404d7c000f686c29816",
            "3:1c4095d3f122d13536f757de3e172fe04e6061a54d2d25ad193f2a2cd40739c1",
            "4:1cd123e18b9e52159af77e5134e5107d3e46cbf287d5c7b183a4b6a11f177e12",
            "5:5623313ab6e6f41e1f33fa551e95f533d4be60e667f825db3961a8d688efe05f",
            "6:3446b0b5f94080a7490c4f09604070fde08cd39bd26fe3f55ce70352328cdbfc",
        ],
        "pks": [
            "0:8d4768421ae667f4b9d2682043b5ed2d558f579a0760f5a914ee29e5eb1f242cda5ae2a94d3458ef8812656abab3aeae",
            "1:890e91ba5c83313ac059cd29b6588b679d13b73488130f93dedb3f3569e8908fe210975ae3048e25bdef9eb32f2a2241",
            "2:984518d5859560096ebdd03d4ff5ff3fced527aae9c4603e0fbfcf66b16adb24e79dce05985fa07cbfb5bed2983a4b64",
            "3:b00e28a1a9ecbfafdd2653ceffd362f9fc4de3d0fafe0b0d6c85828dc66cc6b841ad546dddd22ff7325a15a5043ee192",
            "4:93dc6b076417c4cfcefa364ec0aec3536428ac395a21618a2472576b0ab2a41aff5c69f67fde0eeacc5166ac5471038d",
            "5:b79644dcd8bdc4570d6599354781bb9cced962764db71ca1b31f39a6ceb8309a3a5266d82037512da0ffcc9740d7e2e8",
            "6:a29305ec54f146a4938e973767d38aea79e38122ad6c1284beebffca02f4dad6dfe9d05e1f98774af29bfb60bbdd0b12",
        ],
        "msg": "test message",
        "sigshares": [
            "0:ac8d28f98f3dad1b0d9f1982bb46d64be7d76329a40d477441fd764e4f6a6132351465691f9e27de8bdf140e1b7b6d860e3add01d0f62d99592b0b295c5aa2104192326f213e3c8cea8f3153d29017bfd80b360391e7a376e2d10904f3bfe234",
            "1:94ccaa95e426c49c4ef5ff1e9b439a27ba3a7982fa5922c33fe39d1be1efb8c9d120d6fdf92875e2d15dee5eaebb15f70261d68cfc9dd10114b3c844704184820481854c4c3f1d857ae29ccc2c0328e4e4fd533841b37a3d44911de2f6233958",
            "2:b87809e1e7da4250795a436cca3b3e2422a1bfc816af327c8a0e7b74587d11de6ea94a59b5570b8ac8390dafe93202c3102b2654dea96da55e706b9b0c6d57160743a3ae8aa7379d892a1b007ab58d14b732e5db3945cac549ddf8441c5a8c2a",
            "3:af95f281d7daf4b876833802d96d3be2a355ae01732580deb94e6491740db40ba20d4af2b80a5021340cca38506c19680b17f6340aa430a7ec2c8affa8632193821457113375a6db36a000669dc6a22d0dec2e1062efb5e70ce03f2de83761dc",
            "4:87329d5ae25c3916c07080504e34a5aebb4bc375a40d4c1c40d0976e9395f08f5782be3cb7d7f29d2b6ebc1fc46046fa17ba8c9a98416c20ad63a89995f312a2a8175a7ac5988591566fdb8323049c2b124a96953cf1b1de8529af7ae88706ba",
            "5:8981f5e6dc21ed54a644c381e48bc260ae228c179d6b8b4116e95a0f4b4c11be26cf72af12a0ea010f270b17be6b059a145d33b1b193c2b52a4211d7cd7139b7d75e8163bbd32c6caec55d3fab61c0af6b5cb6ff14b7b2c1ed78362dc3c69428",
            "6:88ffb548fff1e0a8a24562cf67cf82a268a8b038c00ad4ec95f1c9f9c561877acc27514cb5ed0be62b14b2015bb531430e6745cbcfe6ced4c29db6843b20728ad8053fe8653840879655afd3392ff4bfac1a88096dadb5ea75a4ff8112f78024",
        ],
        "sig": "922a68c0560adf38d38a6fd1bee6b98019e39382f70db991dc1d1339c2e3b93c0c991f359688b6e900d8c370ce9ad3fc0b49aa487244b012ad557b6649ae0dd71c84a04e18e0a1739c437de55190d745989a7e7950c799d72b8c260903994edd",
        "ct": "b1ed8d8bdeb519cfb9a390f0d442f403614289861947c597b6286098c49d4dad75dbc3f6f6d98e47b29323333fe836ab89c872f63f8927019d01407f1399d425c4f5e96b7e2d328d2caeb07553ae579948fe6e64490909f9c1774772e68a532a11c04a241ce4f8b1d311669af6eef0a0abbe6a44a3fc0689ccd04f1685edbeba198d16394aa4b8d053b71761c65bcd632b8666da0c36f1372f38ff92",
        "decryption_shares": [
            "0:92c78579b4528dc5885b56e470c9be86e7bfa92469f179af0ab9588a898675bca8d04dca8af95bfb658d675ede7fee64",
            "1:9454cc2ec014ce46435576b8ec941aaf1950cd26bda2fb2c5cb30f2f8c96cc449debcdddfbdcfce83ce17f5889a8c440",
            "2:98b4075610dc44200ad314399d4473c6334afa0dd07721106b377381f9c842e0873dc98f2a22fbfe4fb045317ba7ce05",
            "3:b7de32dad950eb8e9b809ed6caf0df93b5dbbae147d35dc3caeffc9fc67f4d1f1b4a86e410f00820f76519f11cec3624",
            "4:840064152069768acffdc89c6a5860cc66ae61ba82cc8ea3b36843f9d9bfa664b478d41b7735b13d813e647ee43a9c68",
            "5:934614a427e087cea95d25ea7e08e1bfc749068c63d13481216fea7cd7c2600605dbf139e0ae67f5d4f3a304c2605c24",
            "6:b0782daec53462d63688ec00dac6cb211a59f0b967a480f08478c995d7058ee6e70f61fff4d0d7ae08b3aad8a0a0296f",
        ],
    },
    { // testData[3]
        "poly": "6e7c7909fb39d276fbca406d4df808b5938bfc8c263ec7be4567eb53770bf7b643082acb6a62a11e2d3237c67041abaecaa87096ad6e6b78e904ee85dc5b34bd4d3adf7dae2d8baca14c9dfa2859aceceaede33cc81080822aaba464e56f3762",
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
