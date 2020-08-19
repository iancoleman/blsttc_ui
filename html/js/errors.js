ErrorDisplay = function(selector) {

    let el = document.querySelectorAll(selector)[0];

    this.show = function(msg) {
        el.textContent = msg;
        el.classList.remove("hidden");
    }

    this.hide = function() {
        el.classList.add("hidden");
    }

};

let errorMessages = {

    skLength: function(size) {
        let errMsg = "Secret Key length must be ";
        errMsg += (skLen * 2).toString();
        errMsg += " hex chars, ";
        errMsg += size.toString();
        errMsg += " provided.";
        return errMsg;
    },

    pkLength: function(size) {
    let errMsg = "Public Key length must be ";
        errMsg += (pkLen * 2).toString();
        errMsg += " hex chars, ";
        errMsg += size.toString();
        errMsg += " provided.";
        return errMsg;
    },

    sigLength: function(size) {
        let errMsg = "Signature length must be ";
        errMsg += (sigLen * 2).toString();
        errMsg += " hex chars, ";
        errMsg += size.toString();
        errMsg += " provided.";
        return errMsg;
    },

    msgLength: function(size) {
        let errMsg = "Message length must be ";
        errMsg += (maxMsgLen).toString();
        errMsg += " chars, ";
        errMsg += size.toString();
        errMsg += " provided.";
        return errMsg;
    },

    ctLength: function(size) {
        let errMsg = "Ciphertext length must be ";
        errMsg += (ctLen * 2).toString();
        errMsg += " hex chars, ";
        errMsg += size.toString();
        errMsg += " provided.";
        return errMsg;
    },

}
