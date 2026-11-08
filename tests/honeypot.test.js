import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
    bannedIps,
    clearBannedIps,
    createEdgeHoneypotMiddleware,
    deriveOverrideToken,
    isScannerPath
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
});
