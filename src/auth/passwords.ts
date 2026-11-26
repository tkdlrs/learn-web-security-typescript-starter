import argon2 from 'argon2';
import { hash, timingSafeEqual } from 'node:crypto';

export const MAX_PASSWORD_LENGTH = 128;
const LEGACY_SHA256_PATTERN = /^[a-f0-9]{64}$/i;

export async function hashPassword(password: string): Promise<string> {
    if (password.length > MAX_PASSWORD_LENGTH) {
        throw new RangeError(
            `Password must not exceed ${MAX_PASSWORD_LENGTH} characters`,
        );
    }
    //
    // return hash('sha256', password, 'hex');
    return argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: 19 * 1024,
        timeCost: 2,
        parallelism: 1,
    });
}
//
export function legacyHashPassword(password: string): string {
    if (password.length > MAX_PASSWORD_LENGTH) {
        throw new RangeError(
            `Password must not exceed ${MAX_PASSWORD_LENGTH} characters`,
        );
    }
    //
    return hash('sha256', password, 'hex');
}
//
export async function verifyPassword(
    password: string,
    passwordHash: string,
): Promise<boolean> {
    if (password.length > MAX_PASSWORD_LENGTH) {
        return false;
    }

    if (LEGACY_SHA256_PATTERN.test(passwordHash)) {
        //
        const candidateHash = Buffer.from(legacyHashPassword(password), 'hex');
        const storedHash = Buffer.from(passwordHash, 'hex');
        return timingSafeEqual(candidateHash, storedHash);
    }
    //
    if (passwordHash.startsWith('$argon2id$')) {
        return argon2.verify(passwordHash, password);
    }
    //
    return false;
}
