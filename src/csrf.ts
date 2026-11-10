import type { RequestHandler } from 'express';
import { sendErrorPage } from './errors.ts';
import { timingSafeEqual } from 'node:crypto';

export function validateRequestOrigin(appOrigin: string): RequestHandler {
    return (req, res, next) => {
        if (req.method !== 'POST') {
            next();
            return;
        }
        //
        const origin = req.header('Origin');
        if (origin) {
            if (origin === appOrigin) {
                next();
                return;
            }
            //
            sendErrorPage(
                res,
                403,
                'Forbidden',
                "This request didn't come from the app",
            );
            return;
        }
        //
        const referer = req.header('Referer');
        if (referer) {
            try {
                if (new URL(referer).origin === appOrigin) {
                    next();
                    return;
                }
            } catch {
                sendErrorPage(
                    res,
                    403,
                    'Forbidden',
                    "This request didn't come from the app",
                );
                return;
            }
        }
        //
        sendErrorPage(
            res,
            403,
            'Forbidden',
            "This request didn't come from the app",
        );
    };
}

export function csrfTokensMatch(expected: string, actual: unknown): boolean {
    if (typeof actual !== 'string') return false;
    //
    console.log('expected:', expected);
    console.log('actual:', actual);
    //
    const expectedSignature = Buffer.from(expected, 'hex');
    const actualSignature = Buffer.from(actual, 'hex');
    console.log('expectedSignature:', expectedSignature);
    console.log('actualSignature:', actualSignature);
    //
    if (actualSignature.length !== expectedSignature.length) return false;
    //
    if (timingSafeEqual(expectedSignature, actualSignature)) {
        return true;
    } else {
        return false;
    }
}
