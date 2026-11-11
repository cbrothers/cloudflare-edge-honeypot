/**
 * Shared Cloudflare Workers & Pages Edge Honeypot, Scanner Trap & 24-Hour KV IP Ban Engine
 * Repository: https://github.com/cbrothers/cloudflare-edge-honeypot
 */

export const BAN_TTL_MS = 24 * 60 * 60 * 1000;
export const BAN_TTL_SECONDS = 24 * 60 * 60;
export const DEFAULT_OVERRIDE_COOKIE_NAME = '__studio_override';
export const OVERRIDE_COOKIE_MAX_AGE = 2592000; // 30 days in seconds
export const MAX_IN_MEMORY_BANS = 10000;

/**
 * In-memory edge isolate ban table mapping IP -> expiration timestamp (ms).
 * @type {Map<string, number>}
 */
export const bannedIps = new Map();

/**
 * How long a "not banned" answer from KV is trusted before KV is asked again.
 */
export const NEGATIVE_BAN_CACHE_TTL_MS = 60 * 1000;

/**
 * In-memory negative cache mapping IP -> timestamp (ms) until which the IP is
 * known not to be banned in KV. Saves one KV read per request for clean visitors.
 * @type {Map<string, number>}
 */
export const notBannedIps = new Map();

export function clearBannedIps() {
    bannedIps.clear();
    notBannedIps.clear();
}

export const SCANNER_SEGMENTS = [
    '/wp-admin',
    '/wp-login',
    '/wp-content',
    '/wp-includes',
    '/wp-config',
    '/wp-json',
    '/xmlrpc.php',
    '/wlwmanifest.xml',
    '/phpmyadmin',
    '/pma',
    '/myadmin',
    '/vendor/phpunit',
    '/cgi-bin',
    '/actuator',
    '/service-account.json',
    '/firebase-adminsdk',
    '/gcp-credentials.json',
    '/s3_config.json',
    '/secrets.json',
    '/secrets.yml',
    '/application-prod.properties',
    '/next.config.js',
    '/server-status',
    '/telescope/requests',
    '/_ignition/execute-solution',
    '/autodiscover/autodiscover.xml'
];

export const DOTFILE_SEGMENT_REGEX =
    /(?:^|\/)\.(?:env|git|aws|ssh|docker|vscode|ds_store)(?:$|\.|\/|;)/i;
export const SCANNER_EXTENSIONS_REGEX =
    /\.(?:php\d?|phtml|asp|aspx|jsp|jspx|cgi|env|sql|bak|old|orig|swp|ini|conf|yml|yaml|properties)(?:$|\/)/i;

/**
 * Strong signals: no static site serves these, so one request bans the client.
 */
export const STRONG_SCANNER_EXTENSIONS_REGEX =
    /\.(?:php\d?|phtml|asp|aspx|jsp|jspx|cgi|env|sql|swp)(?:$|\/)/i;

/**
 * Weak signals: suspicious, but plausible on a real site or in a mistyped link.
 * The request is refused, but the client is not banned.
 */
export const WEAK_SCANNER_EXTENSIONS_REGEX =
    /\.(?:bak|old|orig|ini|conf|yml|yaml|properties)(?:$|\/)/i;
export const WEAK_SCANNER_SEGMENTS = ['/admin'];

const PARENT_SEGMENT_REGEX = /(?:^|\/)\.\.(?:\/|$)/;

export const VERIFIED_CRAWLER_UA_REGEX =
    /\b(?:googlebot|google-inspectiontool|googleother|storebot-google|adsbot-google|mediapartners-google|apis-google|bingbot|adidxbot|applebot|duckduckbot|slurp|baiduspider|yandexbot|facebookexternalhit|facebot|linkedinbot|twitterbot|slackbot|discordbot)\b/i;

export const GOOGLEBOT_IP_PREFIXES = [
    '66.249.',
    '64.233.172.',
    '64.233.173.',
    '2001:4860:4801:'
];

/**
 * Autonomous systems operated by the crawler owners named in
 * VERIFIED_CRAWLER_UA_REGEX: Google, Microsoft (Bing), Apple, Yandex, Meta,
 * LinkedIn, X/Twitter and Baidu. Compared against `request.cf.asn`.
 */
export const VERIFIED_CRAWLER_ASNS = new Set([15169, 8075, 714, 13238, 32934, 14413, 13414, 55967]);

/**
 * Detects verified search engine and social preview crawlers so they are never
 * written to the 24-hour cross-domain IP ban table and receive 404 + noindex on
 * missing/scanner URLs instead of 403 blocks.
 *
 * A crawler User-Agent is never trusted on its own, because any client can send
 * one. It only counts when Cloudflare's network data corroborates it.
 */
export function isVerifiedCrawler(request, clientIp = '') {
    const cf = request && request.cf ? request.cf : null;
    if (cf && cf.botManagement && cf.botManagement.verifiedBot === true) {
        return true;
    }
    const ip = (clientIp || getClientIp(request) || '').trim().toLowerCase();
    if (ip && GOOGLEBOT_IP_PREFIXES.some((prefix) => ip.startsWith(prefix))) {
        return true;
    }
    if (!cf || !request.headers || typeof request.headers.get !== 'function') {
        return false;
    }
    const ua = request.headers.get('User-Agent') || '';
    if (!ua || !VERIFIED_CRAWLER_UA_REGEX.test(ua)) {
        return false;
    }
    if (typeof cf.verifiedBotCategory === 'string' && cf.verifiedBotCategory.trim()) {
        return true;
    }
    return VERIFIED_CRAWLER_ASNS.has(Number(cf.asn));
}

/**
 * Constant-time string comparison that does not short-circuit on length mismatch.
 */
export function constantTimeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length === 0 || b.length === 0) return false;
    const lenA = a.length;
    const lenB = b.length;
    const maxLen = Math.max(lenA, lenB);
    let diff = lenA ^ lenB;
    for (let i = 0; i < maxLen; i++) {
        const codeA = i < lenA ? a.charCodeAt(i) : 0;
        const codeB = i < lenB ? b.charCodeAt(i) : 0;
        diff |= codeA ^ codeB;
    }
    return diff === 0;
}

/**
 * Derives a deterministic token for the HttpOnly override cookie.
 */
export function deriveOverrideToken(secret, prefix = 'ovr') {
    if (typeof secret !== 'string' || !secret.trim()) return '';
    const trimmed = secret.trim();
    let h1 = 0x811c9dc5;
    let h2 = 0x01000193;
    for (let i = 0; i < trimmed.length; i++) {
        const ch = trimmed.charCodeAt(i);
        h1 ^= ch;
        h1 = Math.imul(h1, 0x01000193) >>> 0;
        h2 ^= ch + i;
        h2 = Math.imul(h2, 0x85ebca6b) >>> 0;
    }
    return `${prefix}_${h1.toString(16).padStart(8, '0')}_${h2.toString(16).padStart(8, '0')}`;
}

/**
 * Percent-decodes a string, leaving malformed escapes (e.g. a literal "50%-off")
 * untouched instead of throwing.
 */
function lenientDecode(value) {
    try {
        return decodeURIComponent(value);
    } catch {
        return value.replace(/(?:%[0-9a-f]{2})+/gi, (run) => {
            try {
                return decodeURIComponent(run);
            } catch {
                return run;
            }
        });
    }
}

function hasScannerSegment(normalized, segments, boundaryChars) {
    for (const seg of segments) {
        let idx = normalized.indexOf(seg);
        while (idx !== -1) {
            const after = normalized[idx + seg.length];
            if (after === undefined || boundaryChars.includes(after)) {
                return true;
            }
            idx = normalized.indexOf(seg, idx + 1);
        }
    }
    return false;
}

/**
 * Inspects a URL pathname for CMS, dotfile, cloud credential, or exploit scanner probes.
 * Returns true for both strong and weak signals; see classifyScannerPath.
 */
export function isScannerPath(pathname, options = {}) {
    return classifyScannerPath(pathname, options) !== null;
}

/**
 * Classifies a URL pathname as a scanner probe.
 * Returns 'strong' (refuse and ban), 'weak' (refuse, do not ban) or null (not a probe).
 */
export function classifyScannerPath(pathname, { allowPaths = null, safePaths = null } = {}) {
    if (!pathname || typeof pathname !== 'string') return null;

    let decoded = lenientDecode(pathname);
    if (decoded.includes('%')) {
        decoded = lenientDecode(decoded);
    }

    const normalized = decoded.replace(/\\/g, '/').replace(/\/+/g, '/').toLowerCase();
    const trimmed = normalized.replace(/\/+$/, '') || '/';

    if (
        normalized === '/' ||
        normalized === '/index.html' ||
        normalized === '/__health' ||
        normalized === '/robots.txt' ||
        normalized === '/sitemap.xml' ||
        normalized === '/favicon.svg' ||
        normalized === '/favicon.png' ||
        normalized === '/apple-touch-icon.png' ||
        normalized === '/favicon.ico' ||
        normalized.startsWith('/cdn-cgi/')
    ) {
        return null;
    }

    const effectiveAllowPaths = allowPaths || safePaths;
    if (effectiveAllowPaths) {
        if (
            typeof effectiveAllowPaths.has === 'function' &&
            (effectiveAllowPaths.has(normalized) || effectiveAllowPaths.has(trimmed))
        ) {
            return null;
        }
        if (
            Array.isArray(effectiveAllowPaths) &&
            (effectiveAllowPaths.includes(normalized) || effectiveAllowPaths.includes(trimmed))
        ) {
            return null;
        }
    }

    // A ".." path segment, not any two dots: "/blog/wait...what" is an ordinary URL.
    if (PARENT_SEGMENT_REGEX.test(normalized) || normalized.includes('\0')) {
        return 'strong';
    }

    if (DOTFILE_SEGMENT_REGEX.test(normalized)) {
        return 'strong';
    }

    if (hasScannerSegment(normalized, SCANNER_SEGMENTS, '/.-_')) {
        return 'strong';
    }

    if (STRONG_SCANNER_EXTENSIONS_REGEX.test(normalized)) {
        return 'strong';
    }

    // Weak segments must be a whole path segment: "/admin" and "/admin/x", not "/admin-guide".
    if (hasScannerSegment(normalized, WEAK_SCANNER_SEGMENTS, '/')) {
        return 'weak';
    }

    if (WEAK_SCANNER_EXTENSIONS_REGEX.test(normalized)) {
        return 'weak';
    }

    return null;
}

export function getClientIp(request) {
    if (!request || !request.headers || typeof request.headers.get !== 'function') {
        return '';
    }
    const cfIp = request.headers.get('CF-Connecting-IP');
    if (cfIp && cfIp.trim()) return cfIp.trim().toLowerCase();
    const xff = request.headers.get('x-forwarded-for');
    if (xff && xff.trim()) {
        return xff.split(',')[0].trim().toLowerCase();
    }
    return '';
}

export function getOverrideSecret(env, fallbackSecret = '') {
    if (env && typeof env.STUDIO_OVERRIDE_KEY === 'string' && env.STUDIO_OVERRIDE_KEY.trim()) {
        return env.STUDIO_OVERRIDE_KEY.trim();
    }
    return fallbackSecret;
}

export function isIpAllowlisted(clientIp, env, fallbackAllowlist = '') {
    const rawAllowlist =
        env && typeof env.ALLOWLIST_IPS === 'string' && env.ALLOWLIST_IPS.trim()
            ? env.ALLOWLIST_IPS
            : fallbackAllowlist;
    if (!clientIp || !rawAllowlist || !rawAllowlist.trim()) {
        return false;
    }
    const normalizedIp = clientIp.trim().toLowerCase();
    const allowed = rawAllowlist
        .split(',')
        .map((ip) => ip.trim().toLowerCase())
        .filter(Boolean);
    return allowed.includes(normalizedIp);
}

export function parseCookies(cookieHeader) {
    const map = new Map();
    if (!cookieHeader || typeof cookieHeader !== 'string') return map;
    for (const part of cookieHeader.split(';')) {
        const eqIdx = part.indexOf('=');
        if (eqIdx === -1) continue;
        const k = part.slice(0, eqIdx).trim();
        let v = part.slice(eqIdx + 1).trim();
        if (v.length >= 2 && v.startsWith('"') && v.endsWith('"')) {
            v = v.slice(1, -1);
        }
        if (k) {
            try {
                map.set(k, decodeURIComponent(v));
            } catch {
                map.set(k, v);
            }
        }
    }
    return map;
}

export function hasValidOverrideCookie(
    request,
    env,
    { cookieName = DEFAULT_OVERRIDE_COOKIE_NAME, tokenPrefix = 'ovr', fallbackSecret = '' } = {}
) {
    const secret = getOverrideSecret(env, fallbackSecret);
    if (!secret || !request || !request.headers) return false;
    const cookieHeader = request.headers.get('Cookie') || request.headers.get('cookie') || '';
    if (!cookieHeader) return false;
    const cookies = parseCookies(cookieHeader);
    const cookieVal = cookies.get(cookieName);
    if (!cookieVal || cookieVal === 'locked') return false;
    const derived = deriveOverrideToken(secret, tokenPrefix);
    return constantTimeEqual(cookieVal, secret) || constantTimeEqual(cookieVal, derived);
}

export function hasValidOverrideSupply(request, url, env, { fallbackSecret = '' } = {}) {
    const secret = getOverrideSecret(env, fallbackSecret);
    if (!secret) return { matched: false, viaQuery: false, viaHeader: false };

    const queryCandidate = url && url.searchParams ? url.searchParams.get('studio_override') : null;
    if (typeof queryCandidate === 'string' && constantTimeEqual(queryCandidate, secret)) {
        return { matched: true, viaQuery: true, viaHeader: false };
    }

    const headerCandidate =
        request && request.headers ? request.headers.get('x-studio-override') : null;
    if (typeof headerCandidate === 'string' && constantTimeEqual(headerCandidate.trim(), secret)) {
        return { matched: true, viaQuery: false, viaHeader: true };
    }

    return { matched: false, viaQuery: false, viaHeader: false };
}

export function buildOverrideCookieHeader(
    secret,
    { cookieName = DEFAULT_OVERRIDE_COOKIE_NAME, tokenPrefix = 'ovr', maxAge = OVERRIDE_COOKIE_MAX_AGE } = {}
) {
    const token = deriveOverrideToken(secret, tokenPrefix);
    return `${cookieName}=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

/**
 * Checks only the in-memory ban table. Synchronous and free of KV calls.
 */
export function isIpBannedInMemory(clientIp, now = Date.now()) {
    if (!clientIp) return false;
    const normalizedIp = clientIp.trim().toLowerCase();
    const memExpiry = bannedIps.get(normalizedIp);
    if (typeof memExpiry !== 'number') return false;
    if (memExpiry > now) return true;
    bannedIps.delete(normalizedIp);
    return false;
}

export async function isIpBanned(clientIp, env, now = Date.now()) {
    if (!clientIp) return false;
    const normalizedIp = clientIp.trim().toLowerCase();

    if (isIpBannedInMemory(normalizedIp, now)) {
        return true;
    }

    const notBannedUntil = notBannedIps.get(normalizedIp);
    if (typeof notBannedUntil === 'number') {
        if (notBannedUntil > now) {
            return false;
        }
        notBannedIps.delete(normalizedIp);
    }

    if (env && env.SECURITY_BANS && typeof env.SECURITY_BANS.get === 'function') {
        try {
            const kvVal = await env.SECURITY_BANS.get(`ban:${normalizedIp}`);
            if (kvVal) {
                let expiresAt = now + BAN_TTL_MS;
                try {
                    const parsed = JSON.parse(kvVal);
                    if (parsed && typeof parsed.expiresAt === 'number') {
                        expiresAt = parsed.expiresAt;
                    }
                } catch {}
                if (expiresAt > now) {
                    bannedIps.set(normalizedIp, expiresAt);
                    return true;
                }
            }
            // KV answered "not banned": remember it so the next requests skip the read.
            if (notBannedIps.size >= MAX_IN_MEMORY_BANS) {
                notBannedIps.clear();
            }
            notBannedIps.set(normalizedIp, now + NEGATIVE_BAN_CACHE_TTL_MS);
        } catch {}
    }

    return false;
}

export async function banIp(clientIp, pathname, env, now = Date.now()) {
    if (!clientIp) return;
    const normalizedIp = clientIp.trim().toLowerCase();
    const expiresAt = now + BAN_TTL_MS;

    if (bannedIps.size >= MAX_IN_MEMORY_BANS && !bannedIps.has(normalizedIp)) {
        for (const [ip, exp] of bannedIps.entries()) {
            if (exp <= now) bannedIps.delete(ip);
        }
        if (bannedIps.size >= MAX_IN_MEMORY_BANS) {
            const oldestKey = bannedIps.keys().next().value;
            if (oldestKey !== undefined) bannedIps.delete(oldestKey);
        }
    }

    bannedIps.set(normalizedIp, expiresAt);
    notBannedIps.delete(normalizedIp);

    if (env && env.SECURITY_BANS && typeof env.SECURITY_BANS.put === 'function') {
        try {
            const payload = JSON.stringify({
                ip: normalizedIp,
                path: pathname,
                bannedAt: now,
                expiresAt
            });
            await env.SECURITY_BANS.put(`ban:${normalizedIp}`, payload, {
                expirationTtl: BAN_TTL_SECONDS
            });
        } catch {}
    }
}

export async function unbanIp(clientIp, env) {
    if (!clientIp) return;
    const normalizedIp = clientIp.trim().toLowerCase();
    bannedIps.delete(normalizedIp);

    if (env && env.SECURITY_BANS && typeof env.SECURITY_BANS.delete === 'function') {
        try {
            await env.SECURITY_BANS.delete(`ban:${normalizedIp}`);
        } catch {}
    }
}

export function createForbiddenResponse(reason = 'Access Denied', extraHeaders = {}) {
    return new Response(`Access Denied // Security Telemetry Logged (${reason})`, {
        status: 403,
        statusText: 'Forbidden',
        headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'Cache-Control': 'no-store',
            'CDN-Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff',
            'X-Robots-Tag': 'noindex, nofollow',
            ...extraHeaders
        }
    });
}

export function createNotFoundScannerResponse(reason = 'Not Found', extraHeaders = {}) {
    return new Response(`Not Found (${reason})`, {
        status: 404,
        statusText: 'Not Found',
        headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'Cache-Control': 'no-store',
            'CDN-Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff',
            'X-Robots-Tag': 'noindex, nofollow',
            ...extraHeaders
        }
    });
}

export function isNonProductionHost(hostname, productionHostnames = []) {
    if (typeof hostname !== 'string' || !hostname.trim()) return false;
    const normalized = hostname.trim().toLowerCase();
    for (const prodHost of productionHostnames) {
        if (typeof prodHost === 'string' && normalized === prodHost.trim().toLowerCase()) {
            return false;
        }
    }
    return true;
}

export function injectStageNoIndexHtml(rawHtml, { isNonProd = false } = {}) {
    if (typeof rawHtml !== 'string' || !rawHtml || !isNonProd) {
        return { html: rawHtml, modified: false };
    }

    if (
        /<head\b/i.test(rawHtml) &&
        !/<meta\b[^>]*\bname\s*=\s*(?:"robots"|'robots')/i.test(rawHtml)
    ) {
        const html = rawHtml.replace(
            /(<head\b[^>]*>)/i,
            '$1\n<meta name="robots" content="noindex, nofollow">'
        );
        return { html, modified: true };
    }

    return { html: rawHtml, modified: false };
}

/**
 * Evaluates the honeypot, IP ban, and owner override state for an incoming request.
 * Returns `{ blockedResponse, setCookieHeader }`.
 */
export async function evaluateHoneypotRequest({
    request,
    url,
    env = {},
    now = Date.now(),
    cookieName = DEFAULT_OVERRIDE_COOKIE_NAME,
    tokenPrefix = 'ovr',
    allowPaths = null
}) {
    const clientIp = getClientIp(request);
    let setCookieHeader = null;

    const overrideCheck = hasValidOverrideSupply(request, url, env);
    if (overrideCheck.matched) {
        await unbanIp(clientIp, env);
        const secret = getOverrideSecret(env);
        setCookieHeader = buildOverrideCookieHeader(secret, { cookieName, tokenPrefix });

        if (isScannerPath(url.pathname, { allowPaths })) {
            return {
                blockedResponse: createForbiddenResponse(
                    'Scanner Probe Blocked // Owner Override Active',
                    { 'Set-Cookie': setCookieHeader }
                ),
                setCookieHeader
            };
        }
        return { blockedResponse: null, setCookieHeader };
    }

    const hasCookieOverride = hasValidOverrideCookie(request, env, { cookieName, tokenPrefix });
    const isExemptOwner = hasCookieOverride || isIpAllowlisted(clientIp, env);
    if (isExemptOwner) {
        if (clientIp && bannedIps.has(clientIp)) {
            await unbanIp(clientIp, env);
        }
        if (isScannerPath(url.pathname, { allowPaths })) {
            return {
                blockedResponse: createForbiddenResponse('Scanner Probe Blocked // Exempt Owner IP'),
                setCookieHeader: null
            };
        }
        return { blockedResponse: null, setCookieHeader: null };
    }

    // Verified search engine and social preview crawlers are never banned in memory or KV.
    // If a crawler IP was previously banned, auto-heal it and return 404 + noindex on scanner paths.
    if (isVerifiedCrawler(request, clientIp)) {
        // Only touch KV when a ban actually exists: deletes are a scarce quota.
        if (clientIp && (await isIpBanned(clientIp, env, now))) {
            await unbanIp(clientIp, env);
        }
        if (isScannerPath(url.pathname, { allowPaths })) {
            return {
                blockedResponse: createNotFoundScannerResponse('Scanner Path Not Found'),
                setCookieHeader: null
            };
        }
        return { blockedResponse: null, setCookieHeader: null };
    }

    // Cheapest checks first: memory, then the path itself, and KV only for
    // requests that would otherwise be let through.
    if (isIpBannedInMemory(clientIp, now)) {
        return {
            blockedResponse: createForbiddenResponse('IP Address Banned'),
            setCookieHeader: null
        };
    }

    const probe = classifyScannerPath(url.pathname, { allowPaths });
    if (probe === 'strong') {
        await banIp(clientIp, url.pathname, env, now);
        return {
            blockedResponse: createForbiddenResponse('Honeypot Triggered'),
            setCookieHeader: null
        };
    }
    if (probe === 'weak') {
        return {
            blockedResponse: createForbiddenResponse('Scanner Probe Blocked'),
            setCookieHeader: null
        };
    }

    if (await isIpBanned(clientIp, env, now)) {
        return {
            blockedResponse: createForbiddenResponse('IP Address Banned'),
            setCookieHeader: null
        };
    }

    return { blockedResponse: null, setCookieHeader: null };
}

/**
 * Factory creating a complete Cloudflare Pages / Workers `onRequest` middleware.
 */
export function createEdgeHoneypotMiddleware({
    apexHostname,
    wwwHostname,
    overrideCookieName = DEFAULT_OVERRIDE_COOKIE_NAME,
    tokenPrefix = 'ovr',
    allowPaths = null,
    securityHeaders = null
} = {}) {
    const prodHosts = [apexHostname, wwwHostname].filter(Boolean);

    async function finalizeResponse(request, url, response) {
        if (!response || !response.headers) return response;

        const isNonProd = prodHosts.length > 0 && isNonProductionHost(url && url.hostname, prodHosts);
        const isErrorStatus = typeof response.status === 'number' && response.status >= 400;
        const contentType = (response.headers.get('Content-Type') || '').toLowerCase();
        const isHtml = contentType.includes('text/html');
        const isHead = Boolean(request && request.method === 'HEAD');

        const headers = new Headers(response.headers);
        if (securityHeaders) {
            for (const [k, v] of Object.entries(securityHeaders)) {
                if (!headers.has(k)) {
                    headers.set(k, v);
                }
            }
        }

        if (isNonProd || isErrorStatus) {
            headers.set('X-Robots-Tag', 'noindex, nofollow');
        }

        if (isHtml && !isHead && isNonProd) {
            const rawHtml = await response.text();
            const { html, modified } = injectStageNoIndexHtml(rawHtml, { isNonProd });
            if (modified) {
                headers.delete('Content-Length');
            }
            return new Response(html, {
                status: response.status,
                statusText: response.statusText,
                headers
            });
        }

        if (!isNonProd && !isErrorStatus && !securityHeaders) {
            return response;
        }

        return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers
        });
    }

    async function onRequest(context) {
        const { request, env = {}, next } = context;
        const url = new URL(request.url);
        const now = Date.now();

        if (url.pathname === '/__health') {
            if (request.method !== 'GET' && request.method !== 'HEAD') {
                return finalizeResponse(
                    request,
                    url,
                    new Response('405 Method Not Allowed\n', {
                        status: 405,
                        statusText: 'Method Not Allowed',
                        headers: {
                            Allow: 'GET, HEAD',
                            'Content-Type': 'text/plain; charset=utf-8',
                            'Cache-Control': 'no-store',
                            'CDN-Cache-Control': 'no-store',
                            'X-Content-Type-Options': 'nosniff',
                            'X-Robots-Tag': 'noindex, nofollow'
                        }
                    })
                );
            }
            const body =
                request.method === 'HEAD' ? null : JSON.stringify({ ok: true, status: 'healthy' });
            return finalizeResponse(
                request,
                url,
                new Response(body, {
                    status: 200,
                    headers: {
                        'Content-Type': 'application/json; charset=utf-8',
                        'Cache-Control': 'no-store',
                        'CDN-Cache-Control': 'no-store',
                        'X-Content-Type-Options': 'nosniff'
                    }
                })
            );
        }

        if (
            prodHosts.length > 0 &&
            isNonProductionHost(url.hostname, prodHosts) &&
            url.pathname.toLowerCase() === '/robots.txt'
        ) {
            const body = request.method === 'HEAD' ? null : 'User-agent: *\nDisallow: /\n';
            return new Response(body, {
                status: 200,
                headers: {
                    'Content-Type': 'text/plain; charset=utf-8',
                    'Cache-Control': 'no-store',
                    'CDN-Cache-Control': 'no-store',
                    'X-Content-Type-Options': 'nosniff',
                    'X-Robots-Tag': 'noindex, nofollow'
                }
            });
        }

        const { blockedResponse, setCookieHeader } = await evaluateHoneypotRequest({
            request,
            url,
            env,
            now,
            cookieName: overrideCookieName,
            tokenPrefix,
            allowPaths
        });

        if (blockedResponse) {
            return finalizeResponse(request, url, blockedResponse);
        }

        const upstreamRes =
            typeof next === 'function' ? await next() : new Response('OK', { status: 200 });
        if (!setCookieHeader) {
            return finalizeResponse(request, url, upstreamRes);
        }

        const headers = new Headers(upstreamRes.headers);
        headers.append('Set-Cookie', setCookieHeader);
        headers.set('Cache-Control', 'private, no-store, no-cache, must-revalidate');
        headers.set('CDN-Cache-Control', 'no-store');
        return finalizeResponse(
            request,
            url,
            new Response(upstreamRes.body, {
                status: upstreamRes.status,
                statusText: upstreamRes.statusText,
                headers
            })
        );
    }

    return { onRequest, finalizeResponse };
}
