// Contants

const skLen = 32; // bytes
const pkLen = 48; // bytes
const sigLen = 96; // bytes
const maxMsgLen = 1049600; // bytes
const maxCtLen = 1049600; // bytes

// the number of bytes in a row derived from a BivarPoly
// which varies depending on the threshold.
const row_sizes_by_threshold = [
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
const commitment_sizes_by_threshold = [
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
const poly_sizes_by_threshold = [
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
