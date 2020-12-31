/// <reference types="node" />
export declare function encrypt(bufData: Buffer, bufPublicKey: Buffer): Buffer;
export declare function decrypt(bufData: Buffer, bufPrivateKey: Buffer): Buffer;
export declare function sign(bufData: Buffer, bufPrivateKey: Buffer): Buffer;
export declare function verify(bufData: Buffer, bufSig: Buffer, bufPublicKey: Buffer): Buffer;

export declare function encryptWithPublicKey(bufData: Buffer, bufPublicKey: Buffer): Buffer;
export declare function decryptWithPrivateKey(bufData: Buffer, bufPrivateKey: Buffer): Buffer;
export declare function signByPrivateKey(bufData: Buffer, bufPrivateKey: Buffer): Buffer;
export declare function verifySignatureWithPublicKey(bufData: Buffer, bufSig: Buffer, bufPublicKey: Buffer): Buffer;
