#!/usr/bin/env node
/**
 * Cloudflare Edge Honeypot Telemetry & Stats Viewer (`npm run stats`)
 *
 * Queries:
 * 1. Active 24-hour IP bans in the shared `SECURITY_BANS` KV namespace
 * 2. 7-day (or custom `--days=N`) Cloudflare GraphQL edge telemetry across all zones,
 *    scored through `classifyScannerPath()` to show how many times each trap path was seen.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { classifyScannerPath } from '../src/index.js';

const ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID || '3fd61ce34cc15f05d0af93a665d5f49f';
const KV_NAMESPACE_ID = process.env.SECURITY_BANS_KV_ID || '8042e1b5ee4b42279489114046987cf6';

function getWranglerToken() {
    if (process.env.CLOUDFLARE_API_TOKEN) {
        return process.env.CLOUDFLARE_API_TOKEN;
    }
    const candidates = [
        path.join(os.homedir(), 'AppData', 'Roaming', 'xdg.config', '.wrangler', 'config', 'default.toml'),
        path.join(os.homedir(), '.wrangler', 'config', 'default.toml'),
        path.join(os.homedir(), '.config', '.wrangler', 'config', 'default.toml')
    ];
    for (const p of candidates) {
        if (fs.existsSync(p)) {
            const raw = fs.readFileSync(p, 'utf8');
            const m = raw.match(/oauth_token\s*=\s*"([^"]+)"/);
            if (m && m[1]) return m[1];
        }
    }
    throw new Error(
        'Could not find Wrangler OAuth token. Run `npx wrangler login` or set CLOUDFLARE_API_TOKEN.'
    );
}

async function cfFetch(url, token, { method = 'GET', body = null, raw = false } = {}) {
    const res = await fetch(url, {
        method,
        headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json'
        },
        body: body ? JSON.stringify(body) : undefined
    });
    const text = await res.text();
    if (!res.ok) {
        throw new Error(`HTTP ${res.status} for ${url}: ${text.slice(0, 200)}`);
    }
    return raw ? text : JSON.parse(text);
}

function formatDuration(ms) {
    if (ms <= 0) return 'expired';
    const totalMin = Math.round(ms / 60000);
    const h = Math.floor(totalMin / 60);
    const m = totalMin % 60;
    return h > 0 ? `${h}h ${String(m).padStart(2, '0')}m` : `${m}m`;
}

async function mapConcurrent(items, concurrency, fn) {
    const results = new Array(items.length);
    let idx = 0;
    async function worker() {
        while (idx < items.length) {
            const current = idx++;
            results[current] = await fn(items[current], current);
        }
    }
    await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, () => worker()));
    return results;
}

async function main() {
    const args = process.argv.slice(2);
    const daysArg = args.find((a) => a.startsWith('--days='));
    const days = daysArg ? Math.max(1, Math.min(30, Number(daysArg.split('=')[1]) || 7)) : 7;
    const limitArg = args.find((a) => a.startsWith('--top='));
    const topN = limitArg ? Math.max(5, Number(limitArg.split('=')[1]) || 35) : 35;

    const token = getWranglerToken();
    const now = Date.now();

    console.log('================================================================================');
    console.log(` CLOUDFLARE EDGE HONEYPOT TELEMETRY (KV Namespace: ${KV_NAMESPACE_ID.slice(0, 8)}...)`);
    console.log('================================================================================\n');

    // 1. Fetch active KV bans
    const keysUrl = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/storage/kv/namespaces/${KV_NAMESPACE_ID}/keys?prefix=ban:&limit=1000`;
    const keysResp = await cfFetch(keysUrl, token);
    const keys = keysResp.result || [];

    const banRecords = await mapConcurrent(keys, 12, async (k) => {
        const valUrl = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/storage/kv/namespaces/${KV_NAMESPACE_ID}/values/${encodeURIComponent(k.name)}`;
        try {
            const raw = await cfFetch(valUrl, token, { raw: true });
            const parsed = JSON.parse(raw);
            return {
                key: k.name,
                ip: parsed.ip || k.name.replace(/^ban:/, ''),
                path: parsed.path || '(unknown)',
                host: parsed.host || '',
                country: parsed.country || '',
                city: parsed.city || '',
                asOrganization: parsed.asOrganization || '',
                bannedAt: parsed.bannedAt || 0,
                expiresAt: parsed.expiresAt || 0
            };
        } catch {
            return {
                key: k.name,
                ip: k.name.replace(/^ban:/, ''),
                path: '(unreadable)',
                host: '',
                country: '',
                city: '',
                asOrganization: '',
                bannedAt: 0,
                expiresAt: 0
            };
        }
    });

    banRecords.sort((a, b) => b.bannedAt - a.bannedAt);

    // Group active bans by trigger path
    const activeByPath = new Map();
    for (const b of banRecords) {
        activeByPath.set(b.path, (activeByPath.get(b.path) || 0) + 1);
    }
    const sortedActivePaths = [...activeByPath.entries()].sort((a, b) => b[1] - a[1]);

    console.log(`1. ACTIVE 24-HOUR IP BANS IN KV: ${banRecords.length} IPs currently banned`);
    console.log('--------------------------------------------------------------------------------');
    if (sortedActivePaths.length === 0) {
        console.log('  (No active bans in KV right now)');
    } else {
        console.log('  Active Bans by Trigger Path:');
        for (const [p, count] of sortedActivePaths) {
            console.log(`    ${String(count).padStart(4)} banned IPs  <-  ${p}`);
        }
        console.log('\n  Most Recent 15 Banned IPs:');
        console.log(`    ${'IP Address'.padEnd(36)} ${'Location'.padEnd(18)} ${'TTL Left'.padEnd(9)} Trigger Path`);
        for (const b of banRecords.slice(0, 15)) {
            const ttl = b.expiresAt ? formatDuration(b.expiresAt - now) : 'n/a';
            const loc = [b.country, b.city].filter(Boolean).join('/') || '--';
            console.log(`    ${b.ip.padEnd(36)} ${loc.slice(0, 17).padEnd(18)} ${ttl.padEnd(9)} ${b.path}`);
        }
    }

    // 2. Query 7-day Cloudflare GraphQL edge logs across all zones
    console.log(`\n2. ${days}-DAY HONEYPOT TRAP HIT COUNTS ACROSS ALL CLOUDFLARE ZONES`);
    console.log('--------------------------------------------------------------------------------');

    const zonesResp = await cfFetch('https://api.cloudflare.com/client/v4/zones?per_page=50', token);
    const zones = zonesResp.result || [];

    const startIso = new Date(now - days * 24 * 60 * 60 * 1000).toISOString();
    const endIso = new Date(now).toISOString();

    const gqlQuery = `
    query($zoneTag: string, $start: Time, $end: Time) {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          httpRequestsAdaptiveGroups(
            limit: 500
            filter: {datetime_geq: $start, datetime_leq: $end}
            orderBy: [count_DESC]
          ) {
            count
            dimensions {
              clientCountryName
              clientRequestHTTPHost
              clientRequestPath
              edgeResponseStatus
            }
          }
        }
      }
    }`;

    const pathStats = new Map();
    const zoneTrapTotals = new Map();
    const countryTrapTotals = new Map();
    let totalTrapHits = 0;
    let total403Blocks = 0;

    await mapConcurrent(zones, 6, async (z) => {
        try {
            const res = await cfFetch('https://api.cloudflare.com/client/v4/graphql', token, {
                method: 'POST',
                body: {
                    query: gqlQuery,
                    variables: { zoneTag: z.id, start: startIso, end: endIso }
                }
            });
            const groups = res?.data?.viewer?.zones?.[0]?.httpRequestsAdaptiveGroups || [];
            for (const g of groups) {
                const p = g.dimensions.clientRequestPath;
                const country = g.dimensions.clientCountryName || 'XX';
                const status = g.dimensions.edgeResponseStatus;
                const cnt = g.count;

                if (status === 403) {
                    total403Blocks += cnt;
                }

                const classification = classifyScannerPath(p);
                if (classification) {
                    totalTrapHits += cnt;
                    zoneTrapTotals.set(z.name, (zoneTrapTotals.get(z.name) || 0) + cnt);
                    countryTrapTotals.set(country, (countryTrapTotals.get(country) || 0) + cnt);

                    const existing = pathStats.get(p) || {
                        count: 0,
                        blocked403: 0,
                        type: classification,
                        zones: new Set()
                    };
                    existing.count += cnt;
                    if (status === 403) existing.blocked403 += cnt;
                    existing.zones.add(z.name);
                    pathStats.set(p, existing);
                }
            }
        } catch {
            // Skip zone on error
        }
    });

    const sortedTrapPaths = [...pathStats.entries()].sort((a, b) => b[1].count - a[1].count);
    const sortedZones = [...zoneTrapTotals.entries()].sort((a, b) => b[1] - a[1]);
    const sortedCountries = [...countryTrapTotals.entries()].sort((a, b) => b[1] - a[1]);

    console.log(
        `  Total Honeypot Trap Hits (${days}d): ${totalTrapHits.toLocaleString()} across ${sortedTrapPaths.length} unique trap paths`
    );
    console.log(`  Total 403 Edge Blocks (${days}d):    ${total403Blocks.toLocaleString()} (includes repeat hits from banned IPs)\n`);

    console.log('  Trap Hits by Domain Zone:');
    for (const [zname, cnt] of sortedZones) {
        console.log(`    ${String(cnt).padStart(6)}x  ${zname}`);
    }

    console.log('\n  Top Attacking Countries (Honeypot Trap Hits):');
    for (const [c, cnt] of sortedCountries.slice(0, 12)) {
        console.log(`    ${String(cnt).padStart(6)}x  ${c}`);
    }

    console.log(`\n  Top ${topN} Most-Seen Honeypot Paths (Last ${days} Days):`);
    console.log(`    ${'Total'.padStart(6)}  ${'403s'.padStart(6)}  ${'Signal'.padEnd(7)} ${'Zones'.padEnd(6)} Path`);
    for (const [p, info] of sortedTrapPaths.slice(0, topN)) {
        console.log(
            `    ${String(info.count).padStart(6)}x ${String(info.blocked403).padStart(6)}x  ${info.type.padEnd(7)} ${String(info.zones.size).padStart(2)}     ${p}`
        );
    }
    console.log('================================================================================');
}

main().catch((err) => {
    console.error('Error fetching honeypot stats:', err.message);
    process.exit(1);
});
