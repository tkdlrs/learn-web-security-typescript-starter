import type { Request, Response, NextFunction } from 'express';
import onHeaders from 'on-headers';
// --- Extra middleware to fix the double quote issue.
const doubleQuoteFilename = (value: string): string => {
    return value.replace(
        /(filename\s*=\s*)([^;"]+)/gi,
        (_match, key: string, val: string) => `${key}"${val.trim()}"`,
    );
};
//
export function quoteContentDisposition(
    _req: Request,
    res: Response,
    next: NextFunction,
): void {
    onHeaders(res, () => {
        const cd = res.getHeader('Content-Disposition');
        if (typeof cd === 'string') {
            res.setHeader('Content-Disposition', doubleQuoteFilename(cd));
        }
    });
    next();
}
