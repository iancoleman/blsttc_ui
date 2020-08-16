(function() {

    let clickLocked = false;

    let shares = [];

    let activeCell = {
        from: 0,
        to: 0,
    }

    // the number of bytes in a row derived from a BivarPoly
    // which varies depending on the threshold.
    let row_sizes_by_threshold = [
        40, // threshold 0
        72, // threshold 1
        104, // threshold 2
        136, // threshold 3
        168, // threshold 4
        200, // threshold 5
        232, // threshold 6
        264, // threshold 7
        296, // threshold 8
        328, // threshold 9
        360, // threshold 10
    ]

    // the number of bytes in a commitment derived from a BivarPoly
    // which varies depending on the threshold.
    let commitment_sizes_by_threshold = [
        56, // threshold 0
        104, // threshold 1
        152, // threshold 2
        200, // threshold 3
        248, // threshold 4
        296, // threshold 5
        344, // threshold 6
        392, // threshold 7
        440, // threshold 8
        488, // threshold 9
        536, // threshold 10
    ]

    // the number of bytes in the master secret key (Poly)
    // which varies depending on the threshold.
    let poly_sizes_by_threshold = [
        40, // threshold 0
        72, // threshold 1
        104, // threshold 2
        136, // threshold 3
        168, // threshold 4
        200, // threshold 5
        232, // threshold 6
        264, // threshold 7
        296, // threshold 8
        328, // threshold 9
        360, // threshold 10
    ]

    let Share = function(from, to, totalNodes, threshold) {

        let self = this;

        self.from = from;
        self.to = to;

        // get share creation
        let bytesPerCommitment = commitment_sizes_by_threshold[threshold];
        let commitmentBytes = [];
        for (let i=0; i<bytesPerCommitment; i++) {
            let commitmentByte = wasmExports.get_bivar_commitment_byte(i, from);
            commitmentBytes.push(commitmentByte);
        }
        self.shareCreationHex = uint8ArrayToHex(commitmentBytes);

        // get shares created
        let sharesCreated = [];
        let bytesPerRow = row_sizes_by_threshold[threshold];
        for (let toNode=0; toNode<totalNodes; toNode++) {
            let rowBytes = [];
            for (let i=0; i<bytesPerRow; i++) {
                let rowByte = wasmExports.get_bivar_row_byte(i, from, toNode);
                rowBytes.push(rowByte);
            }
            let rowHex = uint8ArrayToHex(rowBytes);
            sharesCreated.push(rowHex);
        }

        // get shares received
        let sharesReceived = [];
        for (let fromNode=0; fromNode<totalNodes; fromNode++) {
            let rowBytes = [];
            for (let i=0; i<bytesPerRow; i++) {
                let rowByte = wasmExports.get_bivar_row_byte(i, fromNode, to);
                rowBytes.push(rowByte);
            }
            let rowHex = uint8ArrayToHex(rowBytes);
            sharesReceived.push(rowHex);
        }

        // get secret key share
        let sksBytes = [];
        for (let i=0; i<32; i++) {
            let sksByte = wasmExports.get_bivar_sks_byte(i, to);
            sksBytes.push(sksByte);
        }
        self.skshareHex = uint8ArrayToHex(sksBytes);

        // create table cell element
        self.el = document.createElement("td");

        // set text content of cell
        let senderId = from + 1;
        let receiverId = to + 1;
        let content = "F" + senderId + "T" + receiverId;
        self.el.textContent = content;

        // calculate color of cell
        let r = Math.floor(from / totalNodes * 256);
        let b = Math.floor(to / totalNodes * 256);
        let g = 128;
        let rHex = r.toString("16").padStart(2, "0");
        let gHex = g.toString("16").padStart(2, "0");
        let bHex = b.toString("16").padStart(2, "0");
        self.colorHex = "#" + rHex + gHex + bHex;

        self.colorize = function() {
            self.el.style.backgroundColor = self.colorHex;
        }

        self.uncolorize = function() {
            self.el.style.backgroundColor = "rgba(0,0,0,0)";
        }

        self.activate = function() {
            deactivateAll();
            activeCell.from = from;
            activeCell.to = to;
            // higlight row
            for (let i=0; i<totalNodes; i++) {
                let cellIndex = from * totalNodes + i;
                shares[cellIndex].colorize();
            }
            // higlight column
            for (let i=0; i<totalNodes; i++) {
                let cellIndex = totalNodes * i + to;
                shares[cellIndex].colorize();
            }
            // set sender id
            for (let i=0; i<DOM.senderId.length; i++) {
                DOM.senderId[i].textContent = senderId;
            }
            // set receiver id
            for (let i=0; i<DOM.receiverId.length; i++) {
                DOM.receiverId[i].textContent = receiverId;
            }
            // set share creation
            DOM.shareCreation.value = self.shareCreationHex;
            // set shares created
            DOM.sharesCreated.innerHTML = "";
            for (let i=0; i<sharesCreated.length; i++) {
                let action = "Sent by node " + (from+1) + " to node " + (i+1);
                let el = makeShareLineEl(from, i, sharesCreated[i], action);
                DOM.sharesCreated.appendChild(el);
            }
            // set shares received
            DOM.sharesReceived.innerHTML = "";
            for (let i=0; i<sharesReceived.length; i++) {
                let action = "Received by node " + (to+1) + " from node " + (i+1);
                let el = makeShareLineEl(i, to, sharesReceived[i], action);
                DOM.sharesReceived.appendChild(el);
            }
            // set secret key share
            DOM.skshareHex.value = self.skshareHex;
        }

        function deactivateAll() {
            for (let i=0; i<shares.length; i++) {
                shares[i].deactivate();
            }
        }

        self.deactivate = function() {
            // unhiglight row
            for (let i=0; i<totalNodes; i++) {
                let cellIndex = from * totalNodes + i;
                shares[cellIndex].uncolorize();
            }
            // unhiglight column
            for (let i=0; i<totalNodes; i++) {
                let cellIndex = totalNodes * i + to;
                shares[cellIndex].uncolorize();
            }
        }

        function toggleClickLock() {
            clickLocked = !clickLocked;
            for (let i=0; i<shares.length; i++) {
                if (clickLocked) {
                    shares[i].ignoreMouseover();
                }
                else {
                    shares[i].listenForMouseover();
                }
            }
            if (!clickLocked) {
                self.activate();
            }
        }

        self.listenForMouseover = function() {
            self.el.addEventListener("mouseenter", self.activate);
            self.uncolorize();
        }

        self.ignoreMouseover = function() {
            self.el.removeEventListener("mouseenter", self.activate);
        }

        self.bold = function() {
            self.el.classList.add("text-bold");
        }

        self.unbold = function() {
            self.el.classList.remove("text-bold");
        }

        self.fade = function() {
            self.el.classList.add("text-fade");
        }

        self.unfade = function() {
            self.el.classList.remove("text-fade");
        }

        self.el.addEventListener("click", toggleClickLock);

        self.listenForMouseover();

    }

    function makeShareLineEl(from, to, rowHex, action) {
        let el = document.createElement("div");
        // show the hex
        el.textContent = action + ": " + rowHex;
        // get color for this cell
        let i = from * getTotalNodes() + to;
        let colorHex = shares[i].colorHex;
        // add style
        el.style.background = colorHex;
        el.classList.add("shared-secret")
        // pass hover events to parent element
        el.addEventListener("mouseenter", function() {
            el.parentNode.dispatchEvent(new Event("mouseenter"));
        });
        return el;
    }

    let DOM = {};

    DOM.root = document.querySelectorAll("#dkg-keys")[0];
    DOM.generate = DOM.root.querySelectorAll(".generate")[0];
    DOM.totalNodes = DOM.root.querySelectorAll(".total-nodes")[0];
    DOM.threshold = DOM.root.querySelectorAll(".threshold")[0];
    DOM.shares = DOM.root.querySelectorAll(".shares tbody")[0];
    DOM.senderId = DOM.root.querySelectorAll(".sender-id");
    DOM.receiverId = DOM.root.querySelectorAll(".receiver-id");
    DOM.shareCreation = DOM.root.querySelectorAll(".share-creation")[0];
    DOM.sharesCreated = DOM.root.querySelectorAll(".shares-created")[0];
    DOM.sharesReceived = DOM.root.querySelectorAll(".shares-received")[0];
    DOM.skshareHex = DOM.root.querySelectorAll(".skshare-hex")[0];
    DOM.mpkHex = DOM.root.querySelectorAll(".mpk-hex")[0];
    DOM.allSkshares = DOM.root.querySelectorAll(".all-skshares")[0];
    DOM.allShareCreations = DOM.root.querySelectorAll(".all-share-creations")[0];
    DOM.mskPolyHex = DOM.root.querySelectorAll(".msk-poly-hex")[0];
    DOM.error = DOM.root.querySelectorAll(".error")[0];

    DOM.generate.addEventListener("click", generateRandomContributions);
    DOM.shareCreation.addEventListener("mouseenter", boldRow);
    DOM.shareCreation.addEventListener("mouseout", unboldRow);
    DOM.sharesCreated.addEventListener("mouseenter", boldRow);
    DOM.sharesCreated.addEventListener("mouseout", unboldRow);
    DOM.sharesReceived.addEventListener("mouseenter", boldColumn);
    DOM.sharesReceived.addEventListener("mouseout", unboldColumn);
    DOM.skshareHex.addEventListener("mouseenter", boldColumn);
    DOM.skshareHex.addEventListener("mouseout", unboldColumn);
    DOM.mpkHex.addEventListener("mouseenter", boldAll);
    DOM.mpkHex.addEventListener("mouseout", unboldAll);

    function boldRow() {
        let totalCells = getTotalCells();
        if (shares.length != totalCells) {
            return;
        }
        for (i=0; i<totalCells; i++) {
            let share = shares[i];
            if (share.from == activeCell.from) {
                share.bold();
            }
            else {
                share.fade();
            }
        }
    }

    function unboldRow() {
        let totalCells = getTotalCells();
        if (shares.length != totalCells) {
            return;
        }
        for (i=0; i<totalCells; i++) {
            let share = shares[i];
            if (share.from == activeCell.from) {
                share.unbold();
            }
            else {
                share.unfade();
            }
        }
    }

    function boldColumn() {
        let totalCells = getTotalCells();
        if (shares.length != totalCells) {
            return;
        }
        for (i=0; i<totalCells; i++) {
            let share = shares[i];
            if (share.to == activeCell.to) {
                share.bold();
            }
            else {
                share.fade();
            }
        }
    }

    function unboldColumn() {
        let totalCells = getTotalCells();
        if (shares.length != totalCells) {
            return;
        }
        for (i=0; i<totalCells; i++) {
            let share = shares[i];
            if (share.to == activeCell.to) {
                share.unbold();
            }
            else {
                share.unfade();
            }
        }
    }

    function boldAll() {
        for (let i=0; i<shares.length; i++) {
            shares[i].bold();
        }
    }

    function unboldAll() {
        for (let i=0; i<shares.length; i++) {
            shares[i].unbold();
        }
    }

    function getTotalNodes() {
        return parseInt(DOM.totalNodes.value);
    }

    function getTotalCells() {
        let totalNodes = getTotalNodes();
        return totalNodes * totalNodes;
    }

    function showError(msg) {
        DOM.error.textContent = msg;
        DOM.error.classList.remove("hidden");
    }

    function hideError() {
        DOM.error.classList.add("hidden");
        DOM.error.textContent = "";
    }

    function generateRandomContributions() {
        // clear old values
        hideError();
        shares = [];
        DOM.shares.innerHTML = "";
        DOM.mpkHex.value = "";
        DOM.allSkshares.value = "";
        DOM.allShareCreations.value = "";
        DOM.mskPolyHex.value = "";
        DOM.shareCreation.value = "";
        DOM.sharesCreated.innerHTML = "";
        DOM.sharesReceived.innerHTML = "";
        DOM.skshareHex.value = "";
        set_rng_values_wasm();
        // get contribution parameters
        let totalNodes = getTotalNodes();
        let threshold = parseInt(DOM.threshold.value);
        // validate values
        if (totalNodes < 2) {
            showError("Must be at least 2 nodes");
            return;
        }
        if (totalNodes > 10) {
            showError("Must be no more than 10 nodes");
            return;
        }
        if (threshold < 1) {
            showError("Must be at least 1 signing/decrypting node");
            return;
        }
        if (threshold > totalNodes) {
            showError("Cannot have higher threshold than total nodes");
            return;
        }
        wasmExports.generate_bivars(threshold, totalNodes);
        // create contributions
        for (let from=0; from<totalNodes; from++) {
            // create the contribution for this node
            let row = document.createElement("tr");
            for (let to=0; to<totalNodes; to++) {
                let share = new Share(from, to, totalNodes, threshold);
                // keep a record of each share
                shares.push(share);
                // show this cell in the table row
                row.appendChild(share.el);
            }
            // show this row in the table
            DOM.shares.append(row);
        }
        // activate random cell
        firstFrom = Math.floor(totalNodes * Math.random());
        firstTo = Math.floor(totalNodes * Math.random());
        let firstIndex = firstFrom * totalNodes + firstTo;
        shares[firstIndex].activate();
        // show group master public key
        let mpkBytes = [];
        for (let i=0; i<pkLen; i++) {
            let mpkByte = wasmExports.get_mpk_byte(i);
            mpkBytes.push(mpkByte);
        }
        let mpkHex = uint8ArrayToHex(mpkBytes);
        DOM.mpkHex.value = mpkHex;
        // show all skshares
        let skshares = "";
        for (let i=0; i<totalNodes; i++) {
            skshares += shares[i].skshareHex + "\n";
        }
        DOM.allSkshares.value = skshares.trim();
        // show all bivar commitments
        let bivarCommitments = "";
        for (let i=0; i<totalNodes; i++) {
            bivarCommitments += shares[i*totalNodes].shareCreationHex + "\n";
        }
        DOM.allShareCreations.value = bivarCommitments.trim();
        // show master secret key
        let mskPolySize = poly_sizes_by_threshold[threshold];
        let mskPolyBytes = [];
        for (let i=0; i<mskPolySize; i++) {
            let mskPolyByte = wasmExports.get_poly_byte(i);
            mskPolyBytes.push(mskPolyByte);
        }
        let mskPolyHex = uint8ArrayToHex(mskPolyBytes);
        DOM.mskPolyHex.value = mskPolyHex;
    }

})();
