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

let skErrMsg = function(size) {
    let errMsg = "Secret Key length must be ";
    errMsg += (skLen * 2).toString();
    errMsg += " hex chars, ";
    errMsg += size.toString();
    errMsg += " provided.";
    return errMsg;
}

let pkErrMsg = function(size) {
    let errMsg = "Public Key length must be ";
    errMsg += (pkLen * 2).toString();
    errMsg += " hex chars, ";
    errMsg += size.toString();
    errMsg += " provided.";
    return errMsg;
}

let sigErrMsg = function(size) {
    let errMsg = "Signature length must be ";
    errMsg += (sigLen * 2).toString();
    errMsg += " hex chars, ";
    errMsg += size.toString();
    errMsg += " provided.";
    return errMsg;
}

let msgErrMsg = function(size) {
    let errMsg = "Message length must be ";
    errMsg += (maxMsgLen).toString();
    errMsg += " chars, ";
    errMsg += size.toString();
    errMsg += " provided.";
    return errMsg;
}

let ctErrMsg = function(size) {
    let errMsg = "Ciphertext length must be ";
    errMsg += (ctLen * 2).toString();
    errMsg += " hex chars, ";
    errMsg += size.toString();
    errMsg += " provided.";
    return errMsg;
}

deriveError = new ErrorDisplay("#sk-to-pk .error");
signError = new ErrorDisplay("#sign-msg .error");
verifyError = new ErrorDisplay("#verify .error");
encryptError = new ErrorDisplay("#encrypt .error");
decryptError = new ErrorDisplay("#decrypt .error");
