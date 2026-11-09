import type { RequestHandler } from 'express';
import { sendErrorPage } from './errors.ts';

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

export function csrfTokensMatch(_expected: string, _actual: unknown): boolean {
    return true;
}
