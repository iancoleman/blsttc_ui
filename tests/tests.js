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
        ct: "2f4d1f6fa6608329944c835e9fa84c8850e6c3dec2098399bfe45c999b4ab185ab898761cd215f66ae4912cfb27503165f257a9170f0180a059055440693e93cf101591420f441e776a0d6e4eb5e78f971013f68ab246468785faa593ba94881049d5e5243352b3937712de6000000000000000c8c9cb5937519970c153822d13d186a87bcd837a4b6aae78fcdd0b046a98a4c3bafd345a4c6414a6e7986d3a0fc0f72b9"
    },
    { // testData[1]
        "sk": "2264cb509e0217cd217a30990f06dc2a1aa38ea77aa613f7fd4e9a6c58864a8c",
    },
    { // testData[2]
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
            "0:ac8d28f98f3dad1b0d9f1982bb46d64be7d76329a40d477441fd764e4f6a6132351465691f9e27de8bdf140e1b7b6d860e3add01d0f62d99592b0b295c5aa2104192326f213e3c8cea8f3153d29017bfd80b360391e7a376e2d10904f3bfe234",
            "1:a983ff4e2a19c599ee432628eafb6363feddf9b1a72281b1fe3cffbb7bb3c0d438325ab30de46b5ca0eeeb51077006b80e1b65513e4eac3e930fbe835ef7e2f3789cc4897881b9e7b6d2273be1df1e2ed5403e0c76b6deb5d05a90e1874ece77",
            "2:8a310d13e2fef6ba5b2ab5ccd969aa60f5924e6e50b753c2baef1ae6f7b2870e0cc869f0512cfd9e28299593d3d620c414f9e4e6b7e31338200e2dfbd1f1727be730db80450d65318ab6a6f0b60dc118b8cd454ad9da744e7af7ec40b5d6efa9",
            "3:8ea5787a717c8a07d3aceebe2e2c4f6330602d18aa80a51ed3176e557439c19580fa9ae6ef435c87041420e3dfece0e60a41d425a338387daf972eb26e994f2cc734e17e1380ef2355f619f86da8f856f905e3cd6daa923049ff712bad8ae594",
            "4:aad1df81a652aeea0c1ba67f3d9cfc56ba5b54d7d05bcc62a36027ec607088dd1f920bf1dd6612fb9e51bbd9ca7eb9ff12ee4f2c2331c0c3bd0ed98e59bc8355e8d36a18a81fb3c30bbdc3bfcd42fd6e8abdcc6fab1ea41ee5668a84d8e7a49e",
            "5:8fb41e09c5a97d9bf38df0809a4db9a227c032e68dce6c2de527049f867d6c840d4ca056017a787690fc311f31de22000824a580bf01447240e27a881f81e6bc53c9291b05b3381ed1741fc4c8c335bb2adc8e683690eb0aedce217e86a488e0",
            "6:93a764b917a12ff5bd0ddc36c6706df587ea44288e9e7ea1eeca4b6714d795dc810356d0a8aa0038bcbc627a14412ea60259c4e52d964ec55f43daec405a55248758427895c1fb864d841d72d8354ecce5caf25693c41619a0e91f250cfc7876",
        ],
        "sig": "aeb991c8ebca8628d7ed20d79005456a785708ab396f6f44b143c1d1a58bab56fa88c69c8472ba48dc60e20f06ee603511d65834a3fc59a55ff1dc3fa3b1db9e7424d512f5051f212b361fb2ae51a04f1a54522f7fa45cb88b83e0b6db91dd4f",
        "ct": "53e8d024c16aaeb776b081c799127f108aa1b145b6921ca94dc038b11e8921c1d705283a7d56670660c1602fee23671554084ccbde29e1b8664d819c51eb3e4de08e13092c60a8f630935e6fa3bb74fc96868e2e1c1c71b61a239a8e4037e598e4089ef581efb5321a82156e000000000000000c30278cd715d3d9f2d9f6d9999f7eb773f9acfaff9f49f9a82a301b139dfd0a8f0a4f68f61ba59567d3aff06e1ec641ad",
        "decryption_shares": [
            "0:db9fcc6657e5022c788277894f22460a960d2c242084af3be4897094e999c172e9dd4c60af5e05de1751cc743acc59ae",
            "1:ecfd4e17d1579447e1975845f1330f6110b9bee6103f694067dbec1a1bc14e1eab8fc2c0ad5a87406d2ab41ee9b9d4ab",
            "2:ae02c27453d8b0ca6b3d859fdbeebd63934c01af35f4eefc0da41b016cb9ef747d66c073bf2218b4f2dd7ebf219e6ca1",
            "3:7575a6747b8f052dc5d48566b0342a7dcfa054738cac38247cfa6462bf8a7b92f149ada2dc61bbb5d55ed617c8e10680",
            "4:875905941b9f443974f42a0422dc93239da6c862b39d074cad49e5c7ad554f42ece6a5919f789833eee5aee18c42e3ac",
            "5:404be89e10a68ea88de460e02f07fc1ae91eb063d5b7c30aeebb89987b0b5d9beca43d617314d7e0a32bdc582e7a2c8e",
            "6:3a96967e82ae92d9d66325f1c0b7a1729a28ebd6bdbf6ff7755c1481e7441f9490aee49d6b69184f1c16e3cf905cb680",
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
