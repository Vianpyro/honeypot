// Logging eligibility is deliberately kept independent of the DB transport so
// it can be verified without deployment-specific Worker configuration.

const IGNORE_PATHS = new Set([
    '/favicon.ico',
    '/robots.txt',
    '/sitemap.xml',
    '/.well-known/security.txt',
    '/.well-known/security.json',
    '/.well-known/dmarc-policy',
    '/apple-touch-icon.png',
    '/android-chrome-icon.png',
    '/abuseipdb-verification.html',
]);

export function shouldLogEvent(pathname, isTest, isVerifiedMonitor) {
    return !IGNORE_PATHS.has(pathname) && !isTest && !isVerifiedMonitor;
}
