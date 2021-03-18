let encoding = new (function() {

    // manages the display of data as either
    // hex
    // bytes string
    // ascii

    let self = this;

    this.binaryEncoding = "hex";
    this.messageEncoding = "ascii";

    let binaryHex = document.getElementById("binary-hex");
    let binaryBytes = document.getElementById("binary-bytes");
    let messageAscii = document.getElementById("message-ascii");
    let messageHex = document.getElementById("message-hex");
    let messageBytes = document.getElementById("message-bytes");

    let binaryInputs = document.querySelectorAll("[data-encoding-type='binary']");
    let messageInputs = document.querySelectorAll("[data-encoding-type='message']");

    binaryHex.addEventListener("click", changeBinaryEncoding);
    binaryBytes.addEventListener("click", changeBinaryEncoding);
    messageAscii.addEventListener("click", changeMessageEncoding);
    messageHex.addEventListener("click", changeMessageEncoding);
    messageBytes.addEventListener("click", changeMessageEncoding);

    function changeBinaryEncoding(e) {
        let newEncoding = e.target.value;
        if (self.binaryEncoding == "bytes") {
            if (newEncoding == "hex") {
                for (let i=0; i<binaryInputs.length; i++) {
                    let input = binaryInputs[i];
                    let byteStr = input.value;
                    let bytes = JSON.parse(byteStr);
                    let hex = uint8ArrayToHex(bytes);
                    input.value = hex;
                }
            }
        }
        else if (self.binaryEncoding == "hex") {
            if (newEncoding == "bytes") {
                for (let i=0; i<binaryInputs.length; i++) {
                    let input = binaryInputs[i];
                    let hex = input.value;
                    let bytes = hexToUint8Array(hex);
                    let byteStr = uint8ArrayToByteStr(bytes);
                    input.value = byteStr;
                }
            }
        }
        self.binaryEncoding = newEncoding;
    }

    function changeMessageEncoding(e) {
        let newEncoding = e.target.value;
        if (self.messageEncoding == "ascii") {
            if (newEncoding == "hex") {
                for (let i=0; i<messageInputs.length; i++) {
                    let input = messageInputs[i];
                    let ascii = input.value;
                    let bytes = asciiToUint8Array(ascii);
                    let hex = uint8ArrayToHex(bytes);
                    input.value = hex;
                }
            }
            else if (newEncoding == "bytes") {
                for (let i=0; i<messageInputs.length; i++) {
                    let input = messageInputs[i];
                    let ascii = input.value;
                    let bytes = asciiToUint8Array(ascii);
                    let byteStr = uint8ArrayToByteStr(bytes);
                    input.value = byteStr;
                }
            }
        }
        if (self.messageEncoding == "hex") {
            if (newEncoding == "ascii") {
                for (let i=0; i<messageInputs.length; i++) {
                    let input = messageInputs[i];
                    let hex = input.value;
                    let bytes = hexToUint8Array(hex);
                    let ascii = uint8ArrayToAscii(bytes);
                    input.value = ascii;
                }
            }
            else if (newEncoding == "bytes") {
                for (let i=0; i<messageInputs.length; i++) {
                    let input = messageInputs[i];
                    let hex = input.value;
                    let bytes = hexToUint8Array(hex);
                    let byteStr = uint8ArrayToByteStr(bytes);
                    input.value = byteStr;
                }
            }
        }
        else if (self.messageEncoding == "bytes") {
            if (newEncoding == "ascii") {
                for (let i=0; i<messageInputs.length; i++) {
                    let input = messageInputs[i];
                    let byteStr = input.value;
                    let bytes = JSON.parse(byteStr);
                    let ascii = uint8ArrayToAscii(bytes);
                    input.value = ascii;
                }
            }
            else if (newEncoding == "hex") {
                for (let i=0; i<messageInputs.length; i++) {
                    let input = messageInputs[i];
                    let byteStr = input.value;
                    let bytes = JSON.parse(byteStr);
                    let hex = uint8ArrayToHex(bytes);
                    input.value = hex;
                }
            }
        }
        self.messageEncoding = newEncoding;
    }

    this.parseValue = function(el) {
        let value = el.value;
        let bytes = [];
        let encoding = el.getAttribute("data-encoding-type");
        if (encoding == "binary") {
            if (self.binaryEncoding == "hex") {
                bytes = hexToUint8Array(value);
            }
            else if (self.binaryEncoding == "bytes") {
                bytes = JSON.parse(value);
            }
        }
        else if (encoding == "message") {
            if (self.messageEncoding == "ascii") {
                bytes = asciiToUint8Array(value);
            }
            else if (self.messageEncoding == "hex") {
                bytes = hexToUint8Array(value);
            }
            else if (self.messageEncoding == "bytes") {
                bytes = JSON.parse(value);
            }
        }
        else {
            console.log("Unknown data-encoding-type for el");
            console.log(el);
        }
        return bytes;
    }

    this.updateElWithBytes = function(el, bytes) {
        let value = "";
        let encoding = el.getAttribute("data-encoding-type");
        if (encoding == "binary") {
            if (self.binaryEncoding == "hex") {
                value = uint8ArrayToHex(bytes);
            }
            else if (self.binaryEncoding == "bytes") {
                value = uint8ArrayToByteStr(bytes);
            }
        }
        else if (encoding == "message") {
            if (self.messageEncoding == "ascii") {
                value = uint8ArrayToAscii(bytes);
            }
            else if (self.messageEncoding == "hex") {
                value = uint8ArrayToHex(bytes);
            }
            else if (self.messageEncoding == "bytes") {
                value = uint8ArrayToByteStr(bytes);
            }
        }
        else {
            console.log("Unknown data-encoding-type for el");
            console.log(el);
        }
        el.value = value;
    }

})();
