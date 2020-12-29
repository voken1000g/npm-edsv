const EC = require('elliptic').ec
const ecEncrypt = require('eciesjs').encrypt
const ecDecrypt = require('eciesjs').decrypt

const ec = new EC('secp256k1')

const encryptWithPublicKey = function(bufData, bufPublicKey) {
  return ecEncrypt(bufPublicKey, bufData)
}

const decryptWithPrivateKey = function(bufData, bufPrivateKey) {
  return ecDecrypt(bufPrivateKey, bufData)
}

const signByPrivateKey = function(bufData, bufPrivateKey) {
  const ecKeyPair = ec.keyFromPrivate(bufPrivateKey)
  return Buffer.from(ecKeyPair.sign(bufData).toDER())
}

const verifySignatureWithPublicKey = function(bufData, sig, bufVPub) {
  const ecKeyPair = ec.keyFromPublic(bufVPub)
  return ecKeyPair.verify(bufData, sig)
}

module.exports = {
  encryptWithPublicKey: encryptWithPublicKey,
  decryptWithPrivateKey: decryptWithPrivateKey,
  signByPrivateKey: signByPrivateKey,
  verifySignatureWithPublicKey: verifySignatureWithPublicKey,
}
