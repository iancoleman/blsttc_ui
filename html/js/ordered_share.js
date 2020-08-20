OrderedShare = function(shareIndex, shareHex) {

    let self = this;

    self.shareIndex = shareIndex;
    self.shareHex = shareHex;

    this.toString = function() {
        return self.shareIndex + ":" + self.shareHex;
    }

    this.fromString = function(s) {
        let bits = s.split(":");
        if (bits.length != 2) {
            throw("Invalid OrderedShare format, must be 'i:s'");
        }
        self.shareIndex = parseInt(bits[0]);
        self.shareHex = bits[1];
    }

}
