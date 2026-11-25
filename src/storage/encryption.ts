import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
//
export type EncryptedPayload = {
    nonce: Buffer;
    authTag: Buffer;
    ciphertext: Buffer;
};
//
function validateKey(key: Buffer): void {
    if (!Buffer.isBuffer(key)) {
        throw new Error('Key must be a Buffer');
    }
    if (key.length !== 32) {
        throw new Error('Wrong length');
    }
    //
    return;
}
//
function validatePayload(payload: EncryptedPayload): void {
    if (!Buffer.isBuffer(payload.nonce) || payload.nonce.length !== 12) {
        throw new Error('none must be a Buffer with length 12');
    }
    //
    if (!Buffer.isBuffer(payload.authTag) || payload.authTag.length !== 16) {
        throw new Error('authTag must be a Buffer with length 16');
    }
    //
    if (!Buffer.isBuffer(payload.ciphertext)) {
        throw new Error('ciphertext must be a Buffer');
    }
    //
    return;
}
//
export function encrypt(plaintext: Buffer, key: Buffer): EncryptedPayload {
    validateKey(key);
    //
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, nonce, {
        authTagLength: 16,
    });
    const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();
    //
    return { nonce, ciphertext, authTag };
}
//
export function decrypt(payload: EncryptedPayload, key: Buffer): Buffer {
    validateKey(key);
    validatePayload(payload);
    //
    const decipher = createDecipheriv('aes-256-gcm', key, payload.nonce, {
        authTagLength: 16,
    });
    //
    decipher.setAuthTag(payload.authTag);
    //
    const plaintext = Buffer.concat([
        decipher.update(payload.ciphertext),
        decipher.final(),
    ]);
    //
    return plaintext;
}
//
