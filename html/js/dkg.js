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

    let Share = function(from, to, totalNodes, threshold) {

        let self = this;

        self.from = from;
        self.to = to;

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

    function generateRandomContributions() {
        // clear old table
        shares = [];
        DOM.shares.innerHTML = "";
        // get contribution parameters
        let totalNodes = getTotalNodes();
        let threshold = parseInt(DOM.threshold.value);
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
    }

})();
