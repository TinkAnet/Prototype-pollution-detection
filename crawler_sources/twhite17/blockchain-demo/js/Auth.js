"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __spreadArrays = (this && this.__spreadArrays) || function () {
    for (var s = 0, i = 0, il = arguments.length; i < il; i++) s += arguments[i].length;
    for (var r = Array(s), k = 0, i = 0; i < il; i++)
        for (var a = arguments[i], j = 0, jl = a.length; j < jl; j++, k++)
            r[k] = a[j];
    return r;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.decryptBlock = exports.encryptBlock = exports.decryptAES = exports.encryptAES = exports.deepMerge = void 0;
var aes_1 = __importDefault(require("crypto-js/aes"));
var CryptoJS = __importStar(require("crypto-js"));
var node_rsa_1 = __importDefault(require("node-rsa"));
// merges any number of javascript objects in a recursive fashion
// predicate is a rule that all items in merged into the final object should follow
// this is used to stop others from setting values they shouldn't as shown later
function deepMerge(predicate) {
    var objects = [];
    for (var _i = 1; _i < arguments.length; _i++) {
        objects[_i - 1] = arguments[_i];
    }
    var mergeList = {};
    var newObject = {};
    for (var _a = 0, objects_1 = objects; _a < objects_1.length; _a++) {
        var object = objects_1[_a];
        for (var _b = 0, _c = Object.keys(object); _b < _c.length; _b++) {
            var item = _c[_b];
            if (typeof object[item] === 'object') {
                var prevMergeList = mergeList[item];
                mergeList[item] = (prevMergeList) ? __spreadArrays(prevMergeList, [object[item]]) : [object[item]];
            }
            else {
                if (predicate(item)) {
                    newObject[item] = object[item];
                }
            }
        }
    }
    for (var _d = 0, _e = Object.keys(mergeList); _d < _e.length; _d++) {
        var mergeItem = _e[_d];
        newObject[mergeItem] = deepMerge.apply(void 0, __spreadArrays([predicate], mergeList[mergeItem]));
    }
    return newObject;
}
exports.deepMerge = deepMerge;
// for now this is probably not super secure, I have no idea what crypto-js does behind the scenes here
function encryptAES(data, password) {
    var result = aes_1.default.encrypt(data, password);
    if (result === undefined)
        throw new Error("Cannot Encrypt " + data + " with password " + password);
    return result.toString();
}
exports.encryptAES = encryptAES;
function decryptAES(data, password) {
    var result = aes_1.default.decrypt(data, password);
    if (result === undefined)
        throw new Error("Cannot Decrypt " + data + " with password " + password);
    return result.toString(CryptoJS.enc.Utf8);
}
exports.decryptAES = decryptAES;
function encryptBlock(block, key, host) {
    var data = JSON.stringify(block);
    var keyAES = (Math.floor(Math.random() * 1000000)).toString();
    var keyRSA = new node_rsa_1.default(key);
    var encryptedAESKey = keyRSA.encryptPrivate(keyAES, 'base64');
    return { block: encryptAES(data, keyAES), encryptedAESKey: encryptedAESKey, hostname: host };
}
exports.encryptBlock = encryptBlock;
// potentially unsafe decryption
function decryptBlock(block, key, host) {
    var keyRSA = new node_rsa_1.default(key);
    var keyAES = keyRSA.decryptPublic(block.encryptedAESKey, 'utf-8');
    return JSON.parse(decryptAES(block.block, keyAES));
}
exports.decryptBlock = decryptBlock;
