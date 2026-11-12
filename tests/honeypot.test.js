import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
    BAN_TTL_MS,
    NEGATIVE_BAN_CACHE_TTL_MS,
    bannedIps,
    classifyScannerPath,
    clearBannedIps,
    createEdgeHoneypotMiddleware,
    deriveOverrideToken,
    isIpBanned,
    isScannerPath,
    isVerifiedCrawler,
    notBannedIps
} from '../src/index.js';

describe('cloudflare-edge-honeypot shared module', () => {
    test('detects classic CMS, dotfile, and cloud credential scanner paths', () => {
        assert.equal(isScannerPath('/.env'), true);
        assert.equal(isScannerPath('/.env.production'), true);
        assert.equal(isScannerPath('/.git/config'), true);
        assert.equal(isScannerPath('/.aws/credentials'), true);
        assert.equal(isScannerPath('/.docker/.env'), true);
        assert.equal(isScannerPath('/wp-admin/install.php'), true);
        assert.equal(isScannerPath('/wp-json/batch/v1'), true);
        assert.equal(isScannerPath('/service-account.json'), true);
        assert.equal(isScannerPath('/firebase-adminsdk-fbsvc.json'), true);
        assert.equal(isScannerPath('/gcp-credentials.json'), true);
        assert.equal(isScannerPath('/configs/s3_config.json'), true);
        assert.equal(isScannerPath('/config/secrets.yml'), true);
        assert.equal(isScannerPath('/application-prod.properties'), true);
        assert.equal(isScannerPath('/admin/reports'), true);
        assert.equal(isScannerPath('//images/images/cache.php'), true);

        assert.equal(isScannerPath('/'), false);
        assert.equal(isScannerPath('/index.html'), false);
        assert.equal(isScannerPath('/discography.html'), false);
        assert.equal(isScannerPath('/privacy-policy.html'), false);
        assert.equal(isScannerPath('/__health'), false);
        assert.equal(isScannerPath('/cdn-cgi/rum'), false);
        assert.equal(isScannerPath('/custom.php', { safePaths: ['/custom.php'] }), false);
    });

    test('createEdgeHoneypotMiddleware serves /__health, bans scanners for 24h in memory + KV, and supports owner override', async () => {
        clearBannedIps();
        const { onRequest } = createEdgeHoneypotMiddleware({
            apexHostname: 'example.com',
            wwwHostname: 'www.example.com',
            overrideCookieName: '__test_override',
            tokenPrefix: 'test_ovr'
        });

        const healthRes = await onRequest({
            request: new Request('https://www.example.com/__health', { method: 'GET' }),
            env: {},
            next: async () => new Response('Should not reach next', { status: 500 })
        });
        assert.equal(healthRes.status, 200);
        assert.deepEqual(await healthRes.json(), { ok: true, status: 'healthy' });

        const kvStore = new Map();
        const env = {
            STUDIO_OVERRIDE_KEY: 'secret-override-123',
            SECURITY_BANS: {
                get: async (k) => kvStore.get(k) || null,
                put: async (k, v) => kvStore.set(k, v),
                delete: async (k) => kvStore.delete(k)
            }
        };

        const attackerIp = '198.51.100.77';
        const probeRes = await onRequest({
            request: new Request('https://www.example.com/service-account.json', {
                headers: { 'CF-Connecting-IP': attackerIp }
            }),
            env,
            next: async () => new Response('OK', { status: 200 })
        });
        assert.equal(probeRes.status, 403);
        assert.equal(bannedIps.has(attackerIp), true);
        assert.equal(kvStore.has(`ban:${attackerIp}`), true);

        const blockedRes = await onRequest({
            request: new Request('https://www.example.com/', {
                headers: { 'CF-Connecting-IP': attackerIp }
            }),
            env,
            next: async () => new Response('OK', { status: 200 })
        });
        assert.equal(blockedRes.status, 403);

        const overrideRes = await onRequest({
            request: new Request('https://www.example.com/?studio_override=secret-override-123', {
                headers: { 'CF-Connecting-IP': attackerIp }
            }),
            env,
            next: async () => new Response('OK', { status: 200 })
        });
        assert.equal(overrideRes.status, 200);
        assert.equal(bannedIps.has(attackerIp), false);
        assert.equal(kvStore.has(`ban:${attackerIp}`), false);
        assert.match(
            overrideRes.headers.get('Set-Cookie') || '',
            new RegExp(deriveOverrideToken('secret-override-123', 'test_ovr'))
        );

        const stageRes = await onRequest({
            request: new Request('https://stage.example.com/'),
            env: {},
            next: async () =>
                new Response('<!doctype html><html><head><title>Stage</title></head><body></body></html>', {
                    status: 200,
                    headers: { 'Content-Type': 'text/html; charset=utf-8' }
                })
        });
        assert.equal(stageRes.status, 200);
        assert.equal(stageRes.headers.get('X-Robots-Tag'), 'noindex, nofollow');
        assert.match(await stageRes.text(), /noindex, nofollow/);
    });

    test('never bans verified search crawlers (Googlebot), auto-heals pre-banned crawler IPs, and returns 404 + noindex on scanner paths', async () => {
        clearBannedIps();
        const { onRequest } = createEdgeHoneypotMiddleware({
            apexHostname: 'example.com',
            wwwHostname: 'www.example.com'
        });

        const kvStore = new Map();
        const env = {
            SECURITY_BANS: {
                get: async (k) => kvStore.get(k) || null,
                put: async (k, v) => kvStore.set(k, v),
                delete: async (k) => kvStore.delete(k)
            }
        };

        const googlebotIp = '66.249.66.1';
        assert.equal(
            isVerifiedCrawler(
                new Request('https://www.example.com/', {
                    headers: { 'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' }
                }),
                googlebotIp
            ),
            true
        );

        // Pre-seed a ban for Googlebot IP to verify auto-healing
        kvStore.set(`ban:${googlebotIp}`, JSON.stringify({ ip: googlebotIp, expiresAt: Date.now() + 60000 }));
        bannedIps.set(googlebotIp, Date.now() + 60000);

        const crawlerScanRes = await onRequest({
            request: new Request('https://www.example.com/wp-login.php', {
                headers: {
                    'CF-Connecting-IP': googlebotIp,
                    'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
                }
            }),
            env,
            next: async () => new Response('OK', { status: 200 })
        });
        assert.equal(crawlerScanRes.status, 404);
        assert.equal(crawlerScanRes.headers.get('X-Robots-Tag'), 'noindex, nofollow');
        assert.equal(bannedIps.has(googlebotIp), false);
        assert.equal(kvStore.has(`ban:${googlebotIp}`), false);

        const crawlerHomeRes = await onRequest({
            request: new Request('https://www.example.com/', {
                headers: {
                    'CF-Connecting-IP': googlebotIp,
                    'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
                }
            }),
            env,
            next: async () => new Response('OK', { status: 200 })
        });
        assert.equal(crawlerHomeRes.status, 200);
    });

    function createCountingKv() {
        const store = new Map();
        const calls = { get: 0, put: 0, delete: 0 };
        return {
            store,
            calls,
            binding: {
                get: async (k) => {
                    calls.get++;
                    return store.get(k) || null;
                },
                put: async (k, v) => {
                    calls.put++;
                    store.set(k, v);
                },
                delete: async (k) => {
                    calls.delete++;
                    store.delete(k);
                }
            }
        };
    }

    function makeRequest(path, { ip = '203.0.113.9', ua = '', cf = null } = {}) {
        const headers = { 'CF-Connecting-IP': ip };
        if (ua) headers['User-Agent'] = ua;
        const request = new Request(`https://www.example.com${path}`, { headers });
        if (cf) Object.defineProperty(request, 'cf', { value: cf });
        return request;
    }

    const GOOGLEBOT_UA = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
    const okNext = async () => new Response('OK', { status: 200 });

    test('a crawler User-Agent alone is not trusted: spoofers are banned like any scanner', async () => {
        clearBannedIps();
        const kv = createCountingKv();
        const env = { SECURITY_BANS: kv.binding };
        const { onRequest } = createEdgeHoneypotMiddleware({ apexHostname: 'example.com' });
        const spooferIp = '203.0.113.9';

        assert.equal(isVerifiedCrawler(makeRequest('/', { ua: GOOGLEBOT_UA })), false);
        assert.equal(
            isVerifiedCrawler(makeRequest('/', { ua: GOOGLEBOT_UA, cf: { asn: 64500 } })),
            false
        );

        const probeRes = await onRequest({
            request: makeRequest('/.env', { ip: spooferIp, ua: GOOGLEBOT_UA, cf: { asn: 64500 } }),
            env,
            next: okNext
        });
        assert.equal(probeRes.status, 403);
        assert.equal(bannedIps.has(spooferIp), true);
        assert.equal(kv.store.has(`ban:${spooferIp}`), true);
        assert.equal(kv.calls.delete, 0);
    });

    test('a crawler User-Agent corroborated by Cloudflare network data is exempt', async () => {
        clearBannedIps();
        const kv = createCountingKv();
        const env = { SECURITY_BANS: kv.binding };
        const { onRequest } = createEdgeHoneypotMiddleware({ apexHostname: 'example.com' });
        const crawlerIp = '192.0.2.44';

        assert.equal(
            isVerifiedCrawler(makeRequest('/', { ua: GOOGLEBOT_UA, cf: { asn: 15169 } })),
            true
        );
        assert.equal(
            isVerifiedCrawler(
                makeRequest('/', { ua: 'Mozilla/5.0 (compatible; bingbot/2.0)', cf: { verifiedBotCategory: 'Search Engine Crawler' } })
            ),
            true
        );
        assert.equal(
            isVerifiedCrawler(makeRequest('/', { cf: { botManagement: { verifiedBot: true } } })),
            true
        );
        // A matching network without a crawler User-Agent is just a cloud customer.
        assert.equal(isVerifiedCrawler(makeRequest('/', { ua: 'curl/8.0', cf: { asn: 15169 } })), false);

        const res = await onRequest({
            request: makeRequest('/wp-login.php', { ip: crawlerIp, ua: GOOGLEBOT_UA, cf: { asn: 15169 } }),
            env,
            next: okNext
        });
        assert.equal(res.status, 404);
        assert.equal(bannedIps.has(crawlerIp), false);
        assert.equal(kv.calls.put, 0);
    });

    test('crawler requests do not issue KV deletes unless a ban exists', async () => {
        clearBannedIps();
        const kv = createCountingKv();
        const env = { SECURITY_BANS: kv.binding };
        const { onRequest } = createEdgeHoneypotMiddleware({ apexHostname: 'example.com' });
        const googlebotIp = '66.249.66.7';

        for (const path of ['/', '/about.html', '/wp-login.php', '/']) {
            await onRequest({
                request: makeRequest(path, { ip: googlebotIp, ua: GOOGLEBOT_UA }),
                env,
                next: okNext
            });
        }
        assert.equal(kv.calls.delete, 0);
        assert.equal(kv.calls.get, 1);
    });

    test('ordinary URLs are not treated as probes, and weak signals are refused without a ban', async () => {
        assert.equal(isScannerPath('/blog/wait...what'), false);
        assert.equal(isScannerPath('/releases/v1..2/notes.html'), false);
        assert.equal(isScannerPath('/sale-50%-off'), false);
        assert.equal(isScannerPath('/admin-guide'), false);
        assert.equal(isScannerPath('/blog/admin.html'), false);
        assert.equal(isScannerPath('/AutoDiscover/autodiscover.xml'), false);
        assert.equal(isScannerPath('/autodiscover/autodiscover.xml'), false);

        // Traversal and encoded probes are still caught, including beside a malformed escape.
        assert.equal(classifyScannerPath('/static/..%2f..%2fetc/passwd'), 'strong');
        assert.equal(classifyScannerPath('/a/%2e%2e/secret'), 'strong');
        assert.equal(classifyScannerPath('/%2eenv'), 'strong');
        assert.equal(classifyScannerPath('/50%/%2eenv'), 'strong');
        assert.equal(classifyScannerPath('/%252egit/config'), 'strong');
        assert.equal(classifyScannerPath('/wp-login.php'), 'strong');
        assert.equal(classifyScannerPath('/backup.sql'), 'strong');
        assert.equal(classifyScannerPath('/config/secrets.yml'), 'strong');

        assert.equal(classifyScannerPath('/admin'), 'weak');
        assert.equal(classifyScannerPath('/admin/reports'), 'weak');
        assert.equal(classifyScannerPath('/docs/setup.yml'), 'weak');
        assert.equal(classifyScannerPath('/downloads/notes.old'), 'weak');
        assert.equal(classifyScannerPath('/admin/index.php'), 'strong');
        assert.equal(classifyScannerPath('/discography.html'), null);

        clearBannedIps();
        const kv = createCountingKv();
        const env = { SECURITY_BANS: kv.binding };
        const { onRequest } = createEdgeHoneypotMiddleware({ apexHostname: 'example.com' });
        const visitorIp = '198.51.100.20';

        const weakRes = await onRequest({ request: makeRequest('/admin', { ip: visitorIp }), env, next: okNext });
        assert.equal(weakRes.status, 403);
        assert.equal(bannedIps.has(visitorIp), false);
        assert.equal(kv.calls.put, 0);

        const homeRes = await onRequest({ request: makeRequest('/', { ip: visitorIp }), env, next: okNext });
        assert.equal(homeRes.status, 200);

        const typoRes = await onRequest({ request: makeRequest('/sale-50%-off', { ip: visitorIp }), env, next: okNext });
        assert.equal(typoRes.status, 200);
        assert.equal(bannedIps.has(visitorIp), false);
    });

    test('KV is read once per clean visitor, not at all for probes, and bans from other isolates are still honoured', async () => {
        clearBannedIps();
        const kv = createCountingKv();
        const env = { SECURITY_BANS: kv.binding };
        const { onRequest } = createEdgeHoneypotMiddleware({ apexHostname: 'example.com' });
        const visitorIp = '198.51.100.30';

        for (let i = 0; i < 5; i++) {
            const res = await onRequest({ request: makeRequest('/style.css', { ip: visitorIp }), env, next: okNext });
            assert.equal(res.status, 200);
        }
        assert.equal(kv.calls.get, 1);
        assert.equal(notBannedIps.has(visitorIp), true);

        // A probe is decided from the path alone, and repeat probes cost nothing.
        const scannerIp = '198.51.100.31';
        for (const path of ['/.env', '/wp-login.php', '/.git/config']) {
            const res = await onRequest({ request: makeRequest(path, { ip: scannerIp }), env, next: okNext });
            assert.equal(res.status, 403);
        }
        assert.equal(kv.calls.get, 1);
        assert.equal(kv.calls.put, 1);

        // Being banned clears the "not banned" memory for that IP.
        await onRequest({ request: makeRequest('/.env', { ip: visitorIp }), env, next: okNext });
        assert.equal(notBannedIps.has(visitorIp), false);
        const afterBan = await onRequest({ request: makeRequest('/', { ip: visitorIp }), env, next: okNext });
        assert.equal(afterBan.status, 403);

        // A ban written by another isolate is picked up from KV on first sight of the IP.
        const remoteIp = '198.51.100.32';
        kv.store.set(`ban:${remoteIp}`, JSON.stringify({ ip: remoteIp, expiresAt: Date.now() + 60000 }));
        const remoteRes = await onRequest({ request: makeRequest('/', { ip: remoteIp }), env, next: okNext });
        assert.equal(remoteRes.status, 403);
        assert.equal(bannedIps.has(remoteIp), true);
    });

    test('the not-banned cache expires so later bans are noticed', async () => {
        clearBannedIps();
        const kv = createCountingKv();
        const env = { SECURITY_BANS: kv.binding };
        const ip = '198.51.100.40';
        const t0 = 1_000_000;

        assert.equal(await isIpBanned(ip, env, t0), false);
        kv.store.set(`ban:${ip}`, JSON.stringify({ ip, expiresAt: t0 + BAN_TTL_MS }));
        assert.equal(await isIpBanned(ip, env, t0 + NEGATIVE_BAN_CACHE_TTL_MS - 1), false);
        assert.equal(await isIpBanned(ip, env, t0 + NEGATIVE_BAN_CACHE_TTL_MS + 1), true);
        assert.equal(kv.calls.get, 2);
    });
});
