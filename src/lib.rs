use wasm_bindgen::prelude::*;
use threshold_crypto::{serde_impl::SerdeSecret, SecretKey};

#[wasm_bindgen]
pub fn pk_byte_from_sk(
    i: usize,
    sk_0: u8,
    sk_1: u8,
    sk_2: u8,
    sk_3: u8,
    sk_4: u8,
    sk_5: u8,
    sk_6: u8,
    sk_7: u8,
    sk_8: u8,
    sk_9: u8,
    sk_10: u8,
    sk_11: u8,
    sk_12: u8,
    sk_13: u8,
    sk_14: u8,
    sk_15: u8,
    sk_16: u8,
    sk_17: u8,
    sk_18: u8,
    sk_19: u8,
    sk_20: u8,
    sk_21: u8,
    sk_22: u8,
    sk_23: u8,
    sk_24: u8,
    sk_25: u8,
    sk_26: u8,
    sk_27: u8,
    sk_28: u8,
    sk_29: u8,
    sk_30: u8,
    sk_31: u8
    ) -> u8 {
    let sk_bytes = vec![sk_0, sk_1, sk_2, sk_3, sk_4, sk_5, sk_6, sk_7, sk_8, sk_9, sk_10, sk_11, sk_12, sk_13, sk_14, sk_15, sk_16, sk_17, sk_18, sk_19, sk_20, sk_21, sk_22, sk_23, sk_24, sk_25, sk_26, sk_27, sk_28, sk_29, sk_30, sk_31];
    let sk: SecretKey = bincode::deserialize(&sk_bytes).unwrap();
    let b = sk.public_key().to_bytes().to_vec()[i];
    return b
}

#[wasm_bindgen]
pub fn sk_byte_at_index(i: usize) -> u8 {
    // start with hex
    let sk_hex = "7b4ecc05ecc292110029b0d099994505dd74d84197f995bd9c41fc0843fe201b";
    let pk_hex = "a32fc9479cb20e28326952a8acdb76194e44f1f20a39c787265f54af3611e4db80ebece61638ea42b960289e17a13e97";
    // convert to secret key
    let sk_bytes = parse_hex(&sk_hex);
    let sk: SecretKey = bincode::deserialize(&sk_bytes).unwrap();
    // convert from secret key to bytes
    let sk_response = bincode::serialize(&SerdeSecret(sk)).unwrap();
    // respond with byte at index i from input parameter
    let b = sk_response[i];
    //let b = sk.public_key().to_bytes().to_vec()[2];
    return b
}

// BEGIN SIGN_MSG Autogen code

#[wasm_bindgen]
pub fn sign_msg(
    i: usize, // index of byte in signature to return
    l: usize, // number of bytes in message
    sk_0: u8,
    sk_1: u8,
    sk_2: u8,
    sk_3: u8,
    sk_4: u8,
    sk_5: u8,
    sk_6: u8,
    sk_7: u8,
    sk_8: u8,
    sk_9: u8,
    sk_10: u8,
    sk_11: u8,
    sk_12: u8,
    sk_13: u8,
    sk_14: u8,
    sk_15: u8,
    sk_16: u8,
    sk_17: u8,
    sk_18: u8,
    sk_19: u8,
    sk_20: u8,
    sk_21: u8,
    sk_22: u8,
    sk_23: u8,
    sk_24: u8,
    sk_25: u8,
    sk_26: u8,
    sk_27: u8,
    sk_28: u8,
    sk_29: u8,
    sk_30: u8,
    sk_31: u8,
    msg_0: u8,
    msg_1: u8,
    msg_2: u8,
    msg_3: u8,
    msg_4: u8,
    msg_5: u8,
    msg_6: u8,
    msg_7: u8,
    msg_8: u8,
    msg_9: u8,
    msg_10: u8,
    msg_11: u8,
    msg_12: u8,
    msg_13: u8,
    msg_14: u8,
    msg_15: u8,
    msg_16: u8,
    msg_17: u8,
    msg_18: u8,
    msg_19: u8,
    msg_20: u8,
    msg_21: u8,
    msg_22: u8,
    msg_23: u8,
    msg_24: u8,
    msg_25: u8,
    msg_26: u8,
    msg_27: u8,
    msg_28: u8,
    msg_29: u8,
    msg_30: u8,
    msg_31: u8,
    msg_32: u8,
    msg_33: u8,
    msg_34: u8,
    msg_35: u8,
    msg_36: u8,
    msg_37: u8,
    msg_38: u8,
    msg_39: u8,
    msg_40: u8,
    msg_41: u8,
    msg_42: u8,
    msg_43: u8,
    msg_44: u8,
    msg_45: u8,
    msg_46: u8,
    msg_47: u8,
    msg_48: u8,
    msg_49: u8,
    msg_50: u8,
    msg_51: u8,
    msg_52: u8,
    msg_53: u8,
    msg_54: u8,
    msg_55: u8,
    msg_56: u8,
    msg_57: u8,
    msg_58: u8,
    msg_59: u8,
    msg_60: u8,
    msg_61: u8,
    msg_62: u8,
    msg_63: u8,
    msg_64: u8,
    msg_65: u8,
    msg_66: u8,
    msg_67: u8,
    msg_68: u8,
    msg_69: u8,
    msg_70: u8,
    msg_71: u8,
    msg_72: u8,
    msg_73: u8,
    msg_74: u8,
    msg_75: u8,
    msg_76: u8,
    msg_77: u8,
    msg_78: u8,
    msg_79: u8,
    msg_80: u8,
    msg_81: u8,
    msg_82: u8,
    msg_83: u8,
    msg_84: u8,
    msg_85: u8,
    msg_86: u8,
    msg_87: u8,
    msg_88: u8,
    msg_89: u8,
    msg_90: u8,
    msg_91: u8,
    msg_92: u8,
    msg_93: u8,
    msg_94: u8,
    msg_95: u8,
    msg_96: u8,
    msg_97: u8,
    msg_98: u8,
    msg_99: u8,
    msg_100: u8,
    msg_101: u8,
    msg_102: u8,
    msg_103: u8,
    msg_104: u8,
    msg_105: u8,
    msg_106: u8,
    msg_107: u8,
    msg_108: u8,
    msg_109: u8,
    msg_110: u8,
    msg_111: u8,
    msg_112: u8,
    msg_113: u8,
    msg_114: u8,
    msg_115: u8,
    msg_116: u8,
    msg_117: u8,
    msg_118: u8,
    msg_119: u8,
    msg_120: u8,
    msg_121: u8,
    msg_122: u8,
    msg_123: u8,
    msg_124: u8,
    msg_125: u8,
    msg_126: u8,
    msg_127: u8,
    msg_128: u8,
    msg_129: u8,
    msg_130: u8,
    msg_131: u8,
    msg_132: u8,
    msg_133: u8,
    msg_134: u8,
    msg_135: u8,
    msg_136: u8,
    msg_137: u8,
    msg_138: u8,
    msg_139: u8,
    msg_140: u8,
    msg_141: u8,
    msg_142: u8,
    msg_143: u8,
    msg_144: u8,
    msg_145: u8,
    msg_146: u8,
    msg_147: u8,
    msg_148: u8,
    msg_149: u8,
    msg_150: u8,
    msg_151: u8,
    msg_152: u8,
    msg_153: u8,
    msg_154: u8,
    msg_155: u8,
    msg_156: u8,
    msg_157: u8,
    msg_158: u8,
    msg_159: u8,
    msg_160: u8,
    msg_161: u8,
    msg_162: u8,
    msg_163: u8,
    msg_164: u8,
    msg_165: u8,
    msg_166: u8,
    msg_167: u8,
    msg_168: u8,
    msg_169: u8,
    msg_170: u8,
    msg_171: u8,
    msg_172: u8,
    msg_173: u8,
    msg_174: u8,
    msg_175: u8,
    msg_176: u8,
    msg_177: u8,
    msg_178: u8,
    msg_179: u8,
    msg_180: u8,
    msg_181: u8,
    msg_182: u8,
    msg_183: u8,
    msg_184: u8,
    msg_185: u8,
    msg_186: u8,
    msg_187: u8,
    msg_188: u8,
    msg_189: u8,
    msg_190: u8,
    msg_191: u8,
    msg_192: u8,
    msg_193: u8,
    msg_194: u8,
    msg_195: u8,
    msg_196: u8,
    msg_197: u8,
    msg_198: u8,
    msg_199: u8,
    msg_200: u8,
    msg_201: u8,
    msg_202: u8,
    msg_203: u8,
    msg_204: u8,
    msg_205: u8,
    msg_206: u8,
    msg_207: u8,
    msg_208: u8,
    msg_209: u8,
    msg_210: u8,
    msg_211: u8,
    msg_212: u8,
    msg_213: u8,
    msg_214: u8,
    msg_215: u8,
    msg_216: u8,
    msg_217: u8,
    msg_218: u8,
    msg_219: u8,
    msg_220: u8,
    msg_221: u8,
    msg_222: u8,
    msg_223: u8,
    msg_224: u8,
    msg_225: u8,
    msg_226: u8,
    msg_227: u8,
    msg_228: u8,
    msg_229: u8,
    msg_230: u8,
    msg_231: u8,
    msg_232: u8,
    msg_233: u8,
    msg_234: u8,
    msg_235: u8,
    msg_236: u8,
    msg_237: u8,
    msg_238: u8,
    msg_239: u8,
    msg_240: u8,
    msg_241: u8,
    msg_242: u8,
    msg_243: u8,
    msg_244: u8,
    msg_245: u8,
    msg_246: u8,
    msg_247: u8,
    msg_248: u8,
    msg_249: u8,
    msg_250: u8,
    msg_251: u8,
    msg_252: u8,
    msg_253: u8,
    msg_254: u8,
    msg_255: u8
    ) -> u8 {
    // create secret key vec from input parameters
    let sk_bytes: [u8; 32] = [
        sk_0,
        sk_1,
        sk_2,
        sk_3,
        sk_4,
        sk_5,
        sk_6,
        sk_7,
        sk_8,
        sk_9,
        sk_10,
        sk_11,
        sk_12,
        sk_13,
        sk_14,
        sk_15,
        sk_16,
        sk_17,
        sk_18,
        sk_19,
        sk_20,
        sk_21,
        sk_22,
        sk_23,
        sk_24,
        sk_25,
        sk_26,
        sk_27,
        sk_28,
        sk_29,
        sk_30,
        sk_31
    ];
    let sk: SecretKey = bincode::deserialize(&sk_bytes).unwrap();
    // create msg vec from input parameters
    let mut msg = Vec::new();

    if l > 0 {
        msg.push(msg_0);
    }
    if l > 1 {
        msg.push(msg_1);
    }
    if l > 2 {
        msg.push(msg_2);
    }
    if l > 3 {
        msg.push(msg_3);
    }
    if l > 4 {
        msg.push(msg_4);
    }
    if l > 5 {
        msg.push(msg_5);
    }
    if l > 6 {
        msg.push(msg_6);
    }
    if l > 7 {
        msg.push(msg_7);
    }
    if l > 8 {
        msg.push(msg_8);
    }
    if l > 9 {
        msg.push(msg_9);
    }
    if l > 10 {
        msg.push(msg_10);
    }
    if l > 11 {
        msg.push(msg_11);
    }
    if l > 12 {
        msg.push(msg_12);
    }
    if l > 13 {
        msg.push(msg_13);
    }
    if l > 14 {
        msg.push(msg_14);
    }
    if l > 15 {
        msg.push(msg_15);
    }
    if l > 16 {
        msg.push(msg_16);
    }
    if l > 17 {
        msg.push(msg_17);
    }
    if l > 18 {
        msg.push(msg_18);
    }
    if l > 19 {
        msg.push(msg_19);
    }
    if l > 20 {
        msg.push(msg_20);
    }
    if l > 21 {
        msg.push(msg_21);
    }
    if l > 22 {
        msg.push(msg_22);
    }
    if l > 23 {
        msg.push(msg_23);
    }
    if l > 24 {
        msg.push(msg_24);
    }
    if l > 25 {
        msg.push(msg_25);
    }
    if l > 26 {
        msg.push(msg_26);
    }
    if l > 27 {
        msg.push(msg_27);
    }
    if l > 28 {
        msg.push(msg_28);
    }
    if l > 29 {
        msg.push(msg_29);
    }
    if l > 30 {
        msg.push(msg_30);
    }
    if l > 31 {
        msg.push(msg_31);
    }
    if l > 32 {
        msg.push(msg_32);
    }
    if l > 33 {
        msg.push(msg_33);
    }
    if l > 34 {
        msg.push(msg_34);
    }
    if l > 35 {
        msg.push(msg_35);
    }
    if l > 36 {
        msg.push(msg_36);
    }
    if l > 37 {
        msg.push(msg_37);
    }
    if l > 38 {
        msg.push(msg_38);
    }
    if l > 39 {
        msg.push(msg_39);
    }
    if l > 40 {
        msg.push(msg_40);
    }
    if l > 41 {
        msg.push(msg_41);
    }
    if l > 42 {
        msg.push(msg_42);
    }
    if l > 43 {
        msg.push(msg_43);
    }
    if l > 44 {
        msg.push(msg_44);
    }
    if l > 45 {
        msg.push(msg_45);
    }
    if l > 46 {
        msg.push(msg_46);
    }
    if l > 47 {
        msg.push(msg_47);
    }
    if l > 48 {
        msg.push(msg_48);
    }
    if l > 49 {
        msg.push(msg_49);
    }
    if l > 50 {
        msg.push(msg_50);
    }
    if l > 51 {
        msg.push(msg_51);
    }
    if l > 52 {
        msg.push(msg_52);
    }
    if l > 53 {
        msg.push(msg_53);
    }
    if l > 54 {
        msg.push(msg_54);
    }
    if l > 55 {
        msg.push(msg_55);
    }
    if l > 56 {
        msg.push(msg_56);
    }
    if l > 57 {
        msg.push(msg_57);
    }
    if l > 58 {
        msg.push(msg_58);
    }
    if l > 59 {
        msg.push(msg_59);
    }
    if l > 60 {
        msg.push(msg_60);
    }
    if l > 61 {
        msg.push(msg_61);
    }
    if l > 62 {
        msg.push(msg_62);
    }
    if l > 63 {
        msg.push(msg_63);
    }
    if l > 64 {
        msg.push(msg_64);
    }
    if l > 65 {
        msg.push(msg_65);
    }
    if l > 66 {
        msg.push(msg_66);
    }
    if l > 67 {
        msg.push(msg_67);
    }
    if l > 68 {
        msg.push(msg_68);
    }
    if l > 69 {
        msg.push(msg_69);
    }
    if l > 70 {
        msg.push(msg_70);
    }
    if l > 71 {
        msg.push(msg_71);
    }
    if l > 72 {
        msg.push(msg_72);
    }
    if l > 73 {
        msg.push(msg_73);
    }
    if l > 74 {
        msg.push(msg_74);
    }
    if l > 75 {
        msg.push(msg_75);
    }
    if l > 76 {
        msg.push(msg_76);
    }
    if l > 77 {
        msg.push(msg_77);
    }
    if l > 78 {
        msg.push(msg_78);
    }
    if l > 79 {
        msg.push(msg_79);
    }
    if l > 80 {
        msg.push(msg_80);
    }
    if l > 81 {
        msg.push(msg_81);
    }
    if l > 82 {
        msg.push(msg_82);
    }
    if l > 83 {
        msg.push(msg_83);
    }
    if l > 84 {
        msg.push(msg_84);
    }
    if l > 85 {
        msg.push(msg_85);
    }
    if l > 86 {
        msg.push(msg_86);
    }
    if l > 87 {
        msg.push(msg_87);
    }
    if l > 88 {
        msg.push(msg_88);
    }
    if l > 89 {
        msg.push(msg_89);
    }
    if l > 90 {
        msg.push(msg_90);
    }
    if l > 91 {
        msg.push(msg_91);
    }
    if l > 92 {
        msg.push(msg_92);
    }
    if l > 93 {
        msg.push(msg_93);
    }
    if l > 94 {
        msg.push(msg_94);
    }
    if l > 95 {
        msg.push(msg_95);
    }
    if l > 96 {
        msg.push(msg_96);
    }
    if l > 97 {
        msg.push(msg_97);
    }
    if l > 98 {
        msg.push(msg_98);
    }
    if l > 99 {
        msg.push(msg_99);
    }
    if l > 100 {
        msg.push(msg_100);
    }
    if l > 101 {
        msg.push(msg_101);
    }
    if l > 102 {
        msg.push(msg_102);
    }
    if l > 103 {
        msg.push(msg_103);
    }
    if l > 104 {
        msg.push(msg_104);
    }
    if l > 105 {
        msg.push(msg_105);
    }
    if l > 106 {
        msg.push(msg_106);
    }
    if l > 107 {
        msg.push(msg_107);
    }
    if l > 108 {
        msg.push(msg_108);
    }
    if l > 109 {
        msg.push(msg_109);
    }
    if l > 110 {
        msg.push(msg_110);
    }
    if l > 111 {
        msg.push(msg_111);
    }
    if l > 112 {
        msg.push(msg_112);
    }
    if l > 113 {
        msg.push(msg_113);
    }
    if l > 114 {
        msg.push(msg_114);
    }
    if l > 115 {
        msg.push(msg_115);
    }
    if l > 116 {
        msg.push(msg_116);
    }
    if l > 117 {
        msg.push(msg_117);
    }
    if l > 118 {
        msg.push(msg_118);
    }
    if l > 119 {
        msg.push(msg_119);
    }
    if l > 120 {
        msg.push(msg_120);
    }
    if l > 121 {
        msg.push(msg_121);
    }
    if l > 122 {
        msg.push(msg_122);
    }
    if l > 123 {
        msg.push(msg_123);
    }
    if l > 124 {
        msg.push(msg_124);
    }
    if l > 125 {
        msg.push(msg_125);
    }
    if l > 126 {
        msg.push(msg_126);
    }
    if l > 127 {
        msg.push(msg_127);
    }
    if l > 128 {
        msg.push(msg_128);
    }
    if l > 129 {
        msg.push(msg_129);
    }
    if l > 130 {
        msg.push(msg_130);
    }
    if l > 131 {
        msg.push(msg_131);
    }
    if l > 132 {
        msg.push(msg_132);
    }
    if l > 133 {
        msg.push(msg_133);
    }
    if l > 134 {
        msg.push(msg_134);
    }
    if l > 135 {
        msg.push(msg_135);
    }
    if l > 136 {
        msg.push(msg_136);
    }
    if l > 137 {
        msg.push(msg_137);
    }
    if l > 138 {
        msg.push(msg_138);
    }
    if l > 139 {
        msg.push(msg_139);
    }
    if l > 140 {
        msg.push(msg_140);
    }
    if l > 141 {
        msg.push(msg_141);
    }
    if l > 142 {
        msg.push(msg_142);
    }
    if l > 143 {
        msg.push(msg_143);
    }
    if l > 144 {
        msg.push(msg_144);
    }
    if l > 145 {
        msg.push(msg_145);
    }
    if l > 146 {
        msg.push(msg_146);
    }
    if l > 147 {
        msg.push(msg_147);
    }
    if l > 148 {
        msg.push(msg_148);
    }
    if l > 149 {
        msg.push(msg_149);
    }
    if l > 150 {
        msg.push(msg_150);
    }
    if l > 151 {
        msg.push(msg_151);
    }
    if l > 152 {
        msg.push(msg_152);
    }
    if l > 153 {
        msg.push(msg_153);
    }
    if l > 154 {
        msg.push(msg_154);
    }
    if l > 155 {
        msg.push(msg_155);
    }
    if l > 156 {
        msg.push(msg_156);
    }
    if l > 157 {
        msg.push(msg_157);
    }
    if l > 158 {
        msg.push(msg_158);
    }
    if l > 159 {
        msg.push(msg_159);
    }
    if l > 160 {
        msg.push(msg_160);
    }
    if l > 161 {
        msg.push(msg_161);
    }
    if l > 162 {
        msg.push(msg_162);
    }
    if l > 163 {
        msg.push(msg_163);
    }
    if l > 164 {
        msg.push(msg_164);
    }
    if l > 165 {
        msg.push(msg_165);
    }
    if l > 166 {
        msg.push(msg_166);
    }
    if l > 167 {
        msg.push(msg_167);
    }
    if l > 168 {
        msg.push(msg_168);
    }
    if l > 169 {
        msg.push(msg_169);
    }
    if l > 170 {
        msg.push(msg_170);
    }
    if l > 171 {
        msg.push(msg_171);
    }
    if l > 172 {
        msg.push(msg_172);
    }
    if l > 173 {
        msg.push(msg_173);
    }
    if l > 174 {
        msg.push(msg_174);
    }
    if l > 175 {
        msg.push(msg_175);
    }
    if l > 176 {
        msg.push(msg_176);
    }
    if l > 177 {
        msg.push(msg_177);
    }
    if l > 178 {
        msg.push(msg_178);
    }
    if l > 179 {
        msg.push(msg_179);
    }
    if l > 180 {
        msg.push(msg_180);
    }
    if l > 181 {
        msg.push(msg_181);
    }
    if l > 182 {
        msg.push(msg_182);
    }
    if l > 183 {
        msg.push(msg_183);
    }
    if l > 184 {
        msg.push(msg_184);
    }
    if l > 185 {
        msg.push(msg_185);
    }
    if l > 186 {
        msg.push(msg_186);
    }
    if l > 187 {
        msg.push(msg_187);
    }
    if l > 188 {
        msg.push(msg_188);
    }
    if l > 189 {
        msg.push(msg_189);
    }
    if l > 190 {
        msg.push(msg_190);
    }
    if l > 191 {
        msg.push(msg_191);
    }
    if l > 192 {
        msg.push(msg_192);
    }
    if l > 193 {
        msg.push(msg_193);
    }
    if l > 194 {
        msg.push(msg_194);
    }
    if l > 195 {
        msg.push(msg_195);
    }
    if l > 196 {
        msg.push(msg_196);
    }
    if l > 197 {
        msg.push(msg_197);
    }
    if l > 198 {
        msg.push(msg_198);
    }
    if l > 199 {
        msg.push(msg_199);
    }
    if l > 200 {
        msg.push(msg_200);
    }
    if l > 201 {
        msg.push(msg_201);
    }
    if l > 202 {
        msg.push(msg_202);
    }
    if l > 203 {
        msg.push(msg_203);
    }
    if l > 204 {
        msg.push(msg_204);
    }
    if l > 205 {
        msg.push(msg_205);
    }
    if l > 206 {
        msg.push(msg_206);
    }
    if l > 207 {
        msg.push(msg_207);
    }
    if l > 208 {
        msg.push(msg_208);
    }
    if l > 209 {
        msg.push(msg_209);
    }
    if l > 210 {
        msg.push(msg_210);
    }
    if l > 211 {
        msg.push(msg_211);
    }
    if l > 212 {
        msg.push(msg_212);
    }
    if l > 213 {
        msg.push(msg_213);
    }
    if l > 214 {
        msg.push(msg_214);
    }
    if l > 215 {
        msg.push(msg_215);
    }
    if l > 216 {
        msg.push(msg_216);
    }
    if l > 217 {
        msg.push(msg_217);
    }
    if l > 218 {
        msg.push(msg_218);
    }
    if l > 219 {
        msg.push(msg_219);
    }
    if l > 220 {
        msg.push(msg_220);
    }
    if l > 221 {
        msg.push(msg_221);
    }
    if l > 222 {
        msg.push(msg_222);
    }
    if l > 223 {
        msg.push(msg_223);
    }
    if l > 224 {
        msg.push(msg_224);
    }
    if l > 225 {
        msg.push(msg_225);
    }
    if l > 226 {
        msg.push(msg_226);
    }
    if l > 227 {
        msg.push(msg_227);
    }
    if l > 228 {
        msg.push(msg_228);
    }
    if l > 229 {
        msg.push(msg_229);
    }
    if l > 230 {
        msg.push(msg_230);
    }
    if l > 231 {
        msg.push(msg_231);
    }
    if l > 232 {
        msg.push(msg_232);
    }
    if l > 233 {
        msg.push(msg_233);
    }
    if l > 234 {
        msg.push(msg_234);
    }
    if l > 235 {
        msg.push(msg_235);
    }
    if l > 236 {
        msg.push(msg_236);
    }
    if l > 237 {
        msg.push(msg_237);
    }
    if l > 238 {
        msg.push(msg_238);
    }
    if l > 239 {
        msg.push(msg_239);
    }
    if l > 240 {
        msg.push(msg_240);
    }
    if l > 241 {
        msg.push(msg_241);
    }
    if l > 242 {
        msg.push(msg_242);
    }
    if l > 243 {
        msg.push(msg_243);
    }
    if l > 244 {
        msg.push(msg_244);
    }
    if l > 245 {
        msg.push(msg_245);
    }
    if l > 246 {
        msg.push(msg_246);
    }
    if l > 247 {
        msg.push(msg_247);
    }
    if l > 248 {
        msg.push(msg_248);
    }
    if l > 249 {
        msg.push(msg_249);
    }
    if l > 250 {
        msg.push(msg_250);
    }
    if l > 251 {
        msg.push(msg_251);
    }
    if l > 252 {
        msg.push(msg_252);
    }
    if l > 253 {
        msg.push(msg_253);
    }
    if l > 254 {
        msg.push(msg_254);
    }
    if l > 255 {
        msg.push(msg_255);
    }
    let sig = sk.sign(msg);
    return sig.to_bytes().to_vec()[i]
}

// END SIGN_MSG Autogen code


fn parse_hex(hex_str: &str) -> Vec<u8> {
    let mut hex_bytes = hex_str
        .as_bytes()
        .iter()
        .filter_map(|b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        })
        .fuse();

    let mut bytes = Vec::new();
    while let (Some(h), Some(l)) = (hex_bytes.next(), hex_bytes.next()) {
        bytes.push(h<<4 | l)
    }
    bytes
}

fn vec_to_hex(v: Vec<u8>) -> String {
    v.iter().map(|b| format!("{:02x}", b)).collect()
}
