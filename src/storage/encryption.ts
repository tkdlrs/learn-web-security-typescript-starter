import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
//
const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH_BYTES = 32;
const NONCE_LENGTH_BYTES = 12;
const AUTH_TAG_LENGTH_BYTES = 16;
//
export type EncryptedPayload = {
    nonce: Buffer;
    authTag: Buffer;
    ciphertext: Buffer;
};
//
export function encrypt(plaintext: Buffer, key: Buffer): EncryptedPayload {
    validateKey(key);
    //
    const nonce = randomBytes(NONCE_LENGTH_BYTES);
    const cipher = createCipheriv(ALGORITHM, key, nonce, {
        authTagLength: AUTH_TAG_LENGTH_BYTES,
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
    try {
        const decipher = createDecipheriv(ALGORITHM, key, payload.nonce, {
            authTagLength: AUTH_TAG_LENGTH_BYTES,
        });
        //
        decipher.setAuthTag(payload.authTag);
        //
        const plain = Buffer.concat([
            decipher.update(payload.ciphertext),
            decipher.final(),
        ]);
        //
        return plain;
        //
    } catch {
        throw new Error('Encrypted payload failed authentication');
    }
}
//
function validateKey(key: Buffer): void {
    if (!Buffer.isBuffer(key) || key.length !== KEY_LENGTH_BYTES) {
        throw new Error(`Encryption key must be a ${KEY_LENGTH_BYTES} Buffer`);
    }
}
//
function validatePayload(payload: EncryptedPayload): void {
    if (
        !Buffer.isBuffer(payload.nonce) ||
        payload.nonce.length !== NONCE_LENGTH_BYTES
    ) {
        throw new Error('Invalid encrypted payload (none)');
    }
    //
    if (
        !Buffer.isBuffer(payload.authTag) ||
        payload.authTag.length !== AUTH_TAG_LENGTH_BYTES
    ) {
        throw new Error('Invalid encrypted payload (authTag)');
    }
    //
    if (!Buffer.isBuffer(payload.ciphertext)) {
        throw new Error('Invalid encrypted payload (ciphertext)');
    }
}
//
