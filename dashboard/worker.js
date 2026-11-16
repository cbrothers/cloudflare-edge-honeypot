/**
 * Cloudflare Edge Honeypot Telemetry, All-Traffic Status Matrix & Rule Editor Dashboard Worker
 * (`cf-hp-stats.emerald-glen.com`)
 *
 * Protected behind Cloudflare Access (`*.emerald-glen.com`).
 * - Directly reads/manages active 24h bans from `env.SECURITY_BANS` KV binding
 * - Reads/writes dynamic KV rule overrides (`config:rules` in `env.SECURITY_BANS`)
 * - Queries all HTTP traffic, status codes, and trap telemetry across all 19 Cloudflare zones via `env.CF_ANALYTICS_TOKEN`
 */

import {
    BAN_TTL_MS,
    BAN_TTL_SECONDS,
    SCANNER_SEGMENTS,
    WEAK_SCANNER_SEGMENTS,
    classifyScannerPath,
    getCustomRules,
    saveCustomRules
} from '../src/index.js';

let cachedZoneStats = {
    key: '',
    expiresAt: 0,
    data: null
};

async function mapConcurrent(items, concurrency, fn) {
    const results = new Array(items.length);
    let idx = 0;
    async function worker() {
        while (idx < items.length) {
            const current = idx++;
            results[current] = await fn(items[current], current);
        }
    }
    await Promise.all(
        Array.from({ length: Math.min(concurrency, Math.max(1, items.length)) }, () => worker())
    );
    return results;
}

async function listActiveBansFromKv(env) {
    if (!env || !env.SECURITY_BANS || typeof env.SECURITY_BANS.list !== 'function') {
        return [];
    }
    const listResp = await env.SECURITY_BANS.list({ prefix: 'ban:', limit: 1000 });
    const keys = listResp.keys || [];

    const records = await mapConcurrent(keys, 16, async (k) => {
        try {
            const raw = await env.SECURITY_BANS.get(k.name);
            if (!raw) return null;
            const parsed = JSON.parse(raw);
            return {
                key: k.name,
                ip: parsed.ip || k.name.replace(/^ban:/, ''),
                path: parsed.path || '(unknown)',
                bannedAt: parsed.bannedAt || 0,
                expiresAt: parsed.expiresAt || (k.expiration ? k.expiration * 1000 : 0)
            };
        } catch {
            return {
                key: k.name,
                ip: k.name.replace(/^ban:/, ''),
                path: '(unreadable)',
                bannedAt: 0,
                expiresAt: k.expiration ? k.expiration * 1000 : 0
            };
        }
    });

    return records.filter(Boolean).sort((a, b) => b.bannedAt - a.bannedAt);
}

async function fetchZoneTrapTelemetry(token, days = 7, customRules = null) {
    if (!token) {
        return {
            configured: false,
            error: 'CF_ANALYTICS_TOKEN secret not configured yet.',
            totalRequests: 0,
            totalTrapHits: 0,
            total403Blocks: 0,
            uniqueTrapPaths: 0,
            statusSummary: [],
            domainMatrix: [],
            zones: [],
            paths: [],
            allTrafficRows: [],
            uncaughtPaths: []
        };
    }

    const now = Date.now();
    const rulesHash = customRules ? JSON.stringify(customRules) : '';
    const cacheKey = `${days}:${rulesHash}`;
    if (cachedZoneStats.key === cacheKey && cachedZoneStats.expiresAt > now && cachedZoneStats.data) {
        return cachedZoneStats.data;
    }

    const headers = {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
    };

    const zonesRes = await fetch('https://api.cloudflare.com/client/v4/zones?per_page=50', { headers });
    if (!zonesRes.ok) {
        const errText = await zonesRes.text();
        return {
            configured: true,
            error: `Cloudflare Zones API returned HTTP ${zonesRes.status}: ${errText.slice(0, 180)}`,
            totalRequests: 0,
            totalTrapHits: 0,
            total403Blocks: 0,
            uniqueTrapPaths: 0,
            statusSummary: [],
            domainMatrix: [],
            zones: [],
            paths: [],
            allTrafficRows: [],
            uncaughtPaths: []
        };
    }
    const zonesJson = await zonesRes.json();
    const zones = zonesJson.result || [];

    const startIso = new Date(now - days * 24 * 60 * 60 * 1000).toISOString();
    const endIso = new Date(now).toISOString();

    const gqlQuery = `
    query($zoneTag: string, $start: Time, $end: Time) {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          statusTotals: httpRequestsAdaptiveGroups(
            limit: 100
            filter: {datetime_geq: $start, datetime_leq: $end}
            orderBy: [count_DESC]
          ) {
            count
            dimensions {
              edgeResponseStatus
            }
          }
          pathGroups: httpRequestsAdaptiveGroups(
            limit: 500
            filter: {datetime_geq: $start, datetime_leq: $end}
            orderBy: [count_DESC]
          ) {
            count
            dimensions {
              clientRequestHTTPHost
              clientRequestHTTPMethodName
              clientRequestPath
              edgeResponseStatus
            }
          }
        }
      }
    }`;

    const pathStats = new Map();
    const uncaughtStats = new Map();
    const zoneTrapTotals = new Map();
    const globalStatusCounts = new Map();
    const domainMatrixMap = new Map();
    const allTrafficList = [];

    let totalRequests = 0;
    let totalTrapHits = 0;
    let total403Blocks = 0;

    await mapConcurrent(zones, 6, async (z) => {
        try {
            const r = await fetch('https://api.cloudflare.com/client/v4/graphql', {
                method: 'POST',
                headers,
                body: JSON.stringify({
                    query: gqlQuery,
                    variables: { zoneTag: z.id, start: startIso, end: endIso }
                })
            });
            if (!r.ok) return;
            const res = await r.json();
            const zData = res?.data?.viewer?.zones?.[0] || {};
            const statusGroups = zData.statusTotals || [];
            const pathGroups = zData.pathGroups || [];

            const dMat = {
                zone: z.name,
                total: 0,
                s2xx: 0,
                s3xx: 0,
                s403: 0,
                s404: 0,
                s4xxOther: 0,
                s5xx: 0,
                trapHits: 0
            };

            for (const sg of statusGroups) {
                const st = Number(sg.dimensions.edgeResponseStatus) || 0;
                const cnt = sg.count || 0;
                totalRequests += cnt;
                dMat.total += cnt;
                globalStatusCounts.set(st, (globalStatusCounts.get(st) || 0) + cnt);

                if (st >= 200 && st < 300) dMat.s2xx += cnt;
                else if (st >= 300 && st < 400) dMat.s3xx += cnt;
                else if (st === 403) {
                    dMat.s403 += cnt;
                    total403Blocks += cnt;
                } else if (st === 404) dMat.s404 += cnt;
                else if (st >= 400 && st < 500) dMat.s4xxOther += cnt;
                else if (st >= 500) dMat.s5xx += cnt;
            }

            for (const g of pathGroups) {
                const p = g.dimensions.clientRequestPath;
                const host = g.dimensions.clientRequestHTTPHost || z.name;
                const method = g.dimensions.clientRequestHTTPMethodName || 'GET';
                const status = Number(g.dimensions.edgeResponseStatus) || 0;
                const cnt = g.count || 0;

                const classification = classifyScannerPath(p, { customRules });

                allTrafficList.push({
                    zone: z.name,
                    host,
                    method,
                    path: p,
                    status,
                    count: cnt,
                    classification: classification || 'clean'
                });

                if (classification) {
                    totalTrapHits += cnt;
                    dMat.trapHits += cnt;
                    zoneTrapTotals.set(z.name, (zoneTrapTotals.get(z.name) || 0) + cnt);

                    const existing = pathStats.get(p) || {
                        path: p,
                        count: 0,
                        blocked403: 0,
                        type: classification,
                        statuses: new Set(),
                        zones: new Set()
                    };
                    existing.count += cnt;
                    if (status === 403) existing.blocked403 += cnt;
                    existing.statuses.add(status);
                    existing.zones.add(z.name);
                    pathStats.set(p, existing);
                } else if (
                    status >= 400 &&
                    p !== '/' &&
                    p !== '/robots.txt' &&
                    p !== '/favicon.ico' &&
                    p !== '/sitemap.xml' &&
                    !p.startsWith('/cdn-cgi/')
                ) {
                    const u = uncaughtStats.get(p) || {
                        path: p,
                        count: 0,
                        statuses: new Set(),
                        zones: new Set()
                    };
                    u.count += cnt;
                    u.statuses.add(status);
                    u.zones.add(z.name);
                    uncaughtStats.set(p, u);
                }
            }

            if (dMat.total > 0 || dMat.trapHits > 0) {
                domainMatrixMap.set(z.name, dMat);
            }
        } catch {
            // Ignore single-zone failure
        }
    });

    const sortedPaths = [...pathStats.values()]
        .map((item) => ({
            path: item.path,
            count: item.count,
            blocked403: item.blocked403,
            type: item.type,
            statuses: [...item.statuses].sort((a, b) => a - b),
            zoneCount: item.zones.size,
            zones: [...item.zones].sort()
        }))
        .sort((a, b) => b.count - a.count);

    const sortedUncaught = [...uncaughtStats.values()]
        .map((item) => ({
            path: item.path,
            count: item.count,
            statuses: [...item.statuses].sort((a, b) => a - b),
            zoneCount: item.zones.size
        }))
        .sort((a, b) => b.count - a.count);

    const sortedZones = [...zoneTrapTotals.entries()]
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count);

    const statusSummary = [...globalStatusCounts.entries()]
        .map(([status, count]) => ({ status, count }))
        .sort((a, b) => b.count - a.count);

    const domainMatrix = [...domainMatrixMap.values()].sort((a, b) => b.total - a.total);

    allTrafficList.sort((a, b) => b.count - a.count);

    const data = {
        configured: true,
        error: null,
        days,
        generatedAt: new Date(now).toISOString(),
        totalRequests,
        totalTrapHits,
        total403Blocks,
        uniqueTrapPaths: sortedPaths.length,
        statusSummary,
        domainMatrix,
        zones: sortedZones,
        paths: sortedPaths.slice(0, 150),
        allTrafficRows: allTrafficList.slice(0, 250),
        uncaughtPaths: sortedUncaught.slice(0, 40)
    };

    cachedZoneStats = {
        key: cacheKey,
        expiresAt: now + 60 * 1000,
        data
    };

    return data;
}

function renderDashboardHtml() {
    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>Cloudflare Traffic, Honeypot & Rule Store | Emerald Glen</title>
  <style>
    :root {
      --bg: #0b0f17;
      --panel: #131b29;
      --panel-alt: #182234;
      --border: #25334d;
      --text: #e6edf7;
      --muted: #8fa1bf;
      --accent: #38bdf8;
      --emerald: #10b981;
      --amber: #f59e0b;
      --danger: #f43f5e;
      --purple: #a78bfa;
      --mono: 'JetBrains Mono', 'Cascadia Code', Consolas, monospace;
      --sans: Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      line-height: 1.5;
    }
    header {
      border-bottom: 1px solid var(--border);
      background: rgba(19, 27, 41, 0.92);
      backdrop-filter: blur(10px);
      position: sticky;
      top: 0;
      z-index: 10;
      padding: 1rem 1.5rem;
    }
    .header-inner {
      max-width: 1520px;
      margin: 0 auto;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .badge-live {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      background: rgba(16, 185, 129, 0.15);
      color: var(--emerald);
      border: 1px solid rgba(16, 185, 129, 0.35);
      padding: 0.2rem 0.65rem;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }
    .badge-live::before {
      content: '';
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--emerald);
      box-shadow: 0 0 8px var(--emerald);
    }
    h1 {
      font-size: 1.2rem;
      margin: 0;
      font-weight: 700;
    }
    .controls {
      display: flex;
      align-items: center;
      gap: 0.6rem;
      flex-wrap: wrap;
    }
    button, select, input, textarea {
      background: var(--panel-alt);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.45rem 0.8rem;
      font-size: 0.85rem;
      font-family: inherit;
    }
    textarea {
      font-family: var(--mono);
      font-size: 0.8rem;
      width: 100%;
      min-height: 145px;
      resize: vertical;
      line-height: 1.45;
    }
    button {
      cursor: pointer;
      font-weight: 600;
      transition: background 0.15s, border-color 0.15s;
    }
    button:hover {
      background: #213049;
      border-color: var(--accent);
    }
    button.primary {
      background: rgba(56, 189, 248, 0.15);
      border-color: rgba(56, 189, 248, 0.45);
      color: var(--accent);
    }
    button.emerald {
      background: rgba(16, 185, 129, 0.16);
      border-color: rgba(16, 185, 129, 0.45);
      color: var(--emerald);
    }
    button.danger {
      background: rgba(244, 63, 94, 0.14);
      border-color: rgba(244, 63, 94, 0.4);
      color: #fda4af;
      padding: 0.25rem 0.55rem;
      font-size: 0.75rem;
    }
    button.tiny {
      padding: 0.18rem 0.45rem;
      font-size: 0.72rem;
    }
    main {
      max-width: 1520px;
      margin: 1.5rem auto;
      padding: 0 1.5rem 3rem;
      display: grid;
      gap: 1.5rem;
    }
    .kpis {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 1rem;
    }
    .kpi {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.1rem 1.25rem;
    }
    .kpi-label {
      color: var(--muted);
      font-size: 0.76rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .kpi-val {
      font-size: 1.8rem;
      font-weight: 700;
      font-family: var(--mono);
      margin-top: 0.25rem;
    }
    .kpi-sub {
      color: var(--muted);
      font-size: 0.76rem;
      margin-top: 0.25rem;
    }
    .grid-2 {
      display: grid;
      grid-template-columns: 1.15fr 1fr;
      gap: 1.5rem;
    }
    .grid-4 {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(290px, 1fr));
      gap: 1rem;
      padding: 1.1rem 1.25rem;
    }
    @media (max-width: 1024px) {
      .grid-2 { grid-template-columns: 1fr; }
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
    }
    .card-header {
      padding: 0.95rem 1.25rem;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
      flex-wrap: wrap;
    }
    .card-title {
      font-size: 0.98rem;
      font-weight: 700;
      margin: 0;
    }
    .table-wrap {
      overflow-x: auto;
      max-height: 480px;
      overflow-y: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.83rem;
    }
    th, td {
      padding: 0.52rem 0.85rem;
      text-align: left;
      border-bottom: 1px solid rgba(37, 51, 77, 0.6);
    }
    th {
      background: var(--panel-alt);
      color: var(--muted);
      font-weight: 600;
      font-size: 0.74rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      position: sticky;
      top: 0;
      z-index: 2;
    }
    tr:hover td {
      background: rgba(56, 189, 248, 0.04);
    }
    .mono {
      font-family: var(--mono);
      font-size: 0.79rem;
      word-break: break-all;
    }
    .num {
      font-family: var(--mono);
      text-align: right;
      white-space: nowrap;
    }
    .pill {
      display: inline-block;
      padding: 0.12rem 0.48rem;
      border-radius: 4px;
      font-family: var(--mono);
      font-size: 0.72rem;
      font-weight: 600;
    }
    .pill-strong, .pill-403, .pill-5xx {
      background: rgba(244, 63, 94, 0.16);
      color: #fda4af;
      border: 1px solid rgba(244, 63, 94, 0.35);
    }
    .pill-weak, .pill-404 {
      background: rgba(245, 158, 11, 0.16);
      color: #fcd34d;
      border: 1px solid rgba(245, 158, 11, 0.35);
    }
    .pill-clean, .pill-2xx {
      background: rgba(16, 185, 129, 0.16);
      color: #6ee7b7;
      border: 1px solid rgba(16, 185, 129, 0.35);
    }
    .pill-3xx {
      background: rgba(56, 189, 248, 0.16);
      color: #7dd3fc;
      border: 1px solid rgba(56, 189, 248, 0.35);
    }
    .status-strip {
      display: flex;
      flex-wrap: wrap;
      gap: 0.65rem;
      padding: 0.9rem 1.25rem;
      border-bottom: 1px solid var(--border);
      background: rgba(24, 34, 52, 0.45);
    }
    .status-badge {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      background: var(--panel-alt);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.35rem 0.7rem;
      font-family: var(--mono);
      font-size: 0.79rem;
      cursor: pointer;
    }
    .status-badge:hover {
      border-color: var(--accent);
    }
    .tester-box {
      padding: 1rem 1.25rem;
      display: flex;
      gap: 0.6rem;
      align-items: center;
      flex-wrap: wrap;
      border-top: 1px solid var(--border);
      background: rgba(24, 34, 52, 0.5);
    }
    .rule-col label {
      display: block;
      font-size: 0.8rem;
      font-weight: 700;
      margin-bottom: 0.25rem;
    }
    .rule-col .hint {
      font-size: 0.74rem;
      color: var(--muted);
      margin-bottom: 0.5rem;
    }
    .builtin-chips {
      display: flex;
      flex-wrap: wrap;
      gap: 0.35rem;
      padding: 0.9rem 1.25rem;
      max-height: 220px;
      overflow-y: auto;
      border-top: 1px solid var(--border);
      background: rgba(11, 15, 23, 0.45);
    }
    .chip {
      font-family: var(--mono);
      font-size: 0.73rem;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      background: var(--panel-alt);
      border: 1px solid var(--border);
      cursor: pointer;
      user-select: none;
    }
    .chip.disabled {
      opacity: 0.45;
      text-decoration: line-through;
      border-color: var(--danger);
    }
  </style>
</head>
<body>
  <header>
    <div class="header-inner">
      <div class="brand">
        <span class="badge-live">Edge KV Mesh Active</span>
        <h1>Cloudflare Traffic, Honeypot & Rule Store</h1>
      </div>
      <div class="controls">
        <label for="days-select" style="color:var(--muted);font-size:0.82rem;">Window:</label>
        <select id="days-select">
          <option value="1">Last 24 Hours</option>
          <option value="7" selected>Last 7 Days</option>
          <option value="14">Last 14 Days</option>
        </select>
        <select id="status-filter">
          <option value="">All Return Codes</option>
          <option value="2xx">2xx Success (200/204)</option>
          <option value="3xx">3xx Redirect / Not Mod (301/302/304)</option>
          <option value="403">403 Forbidden / Blocked</option>
          <option value="404">404 Not Found</option>
          <option value="5xx">5xx Origin / SSL Errors</option>
        </select>
        <input type="search" id="path-filter" placeholder="Filter domain, path, IP..." style="min-width:220px;">
        <button class="primary" id="refresh-btn">Refresh Live Data</button>
      </div>
    </div>
  </header>

  <main>
    <section class="kpis">
      <div class="kpi">
        <div class="kpi-label">Total Edge Requests (<span id="kpi-days-label-0">7d</span>)</div>
        <div class="kpi-val" id="kpi-total-reqs">--</div>
        <div class="kpi-sub">All traffic across all 19 Cloudflare zones</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Active 24h KV Bans</div>
        <div class="kpi-val" id="kpi-active-bans" style="color:#fda4af;">--</div>
        <div class="kpi-sub">Shared across all connected domains</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Total Trap Hits (<span id="kpi-days-label">7d</span>)</div>
        <div class="kpi-val" id="kpi-trap-hits" style="color:#fcd34d;">--</div>
        <div class="kpi-sub">Requests matching honeypot signatures</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Total 403 Edge Blocks (<span id="kpi-days-label-2">7d</span>)</div>
        <div class="kpi-val" id="kpi-403-blocks" style="color:#fda4af;">--</div>
        <div class="kpi-sub">Includes repeat hits from banned IPs</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Unique Attack Paths Seen</div>
        <div class="kpi-val" id="kpi-unique-paths">--</div>
        <div class="kpi-sub" id="kpi-rules-count">-- configured rules</div>
      </div>
    </section>

    <!-- All-Traffic & Return Code Summary Across All Domains -->
    <section class="card">
      <div class="card-header">
        <div>
          <h2 class="card-title">All-Traffic & HTTP Return Code Summary (All 19 Cloudflare Zones)</h2>
          <div style="font-size:0.78rem;color:var(--muted);margin-top:0.1rem;">
            Click any HTTP status badge below to filter the request tables by return code, or click a domain row to filter by domain.
          </div>
        </div>
        <span id="telemetry-updated" style="color:var(--muted);font-size:0.78rem;"></span>
      </div>
      <div class="status-strip" id="status-strip">
        <span style="color:var(--muted);font-size:0.82rem;">Loading HTTP status code distribution...</span>
      </div>
      <div class="grid-2" style="gap:0;">
        <div style="border-right:1px solid var(--border);">
          <div class="card-header" style="background:rgba(24,34,52,0.3);">
            <h3 class="card-title" style="font-size:0.88rem;">Per-Domain Traffic & Return Code Breakdown</h3>
          </div>
          <div class="table-wrap" style="max-height:390px;">
            <table>
              <thead>
                <tr>
                  <th>Domain Zone</th>
                  <th style="text-align:right;">Total</th>
                  <th style="text-align:right;color:#6ee7b7;">2xx OK</th>
                  <th style="text-align:right;color:#7dd3fc;">3xx</th>
                  <th style="text-align:right;color:#fda4af;">403 Block</th>
                  <th style="text-align:right;color:#fcd34d;">404</th>
                  <th style="text-align:right;color:#fda4af;">5xx</th>
                  <th style="text-align:right;">Trap Hits</th>
                </tr>
              </thead>
              <tbody id="domain-matrix-tbody">
                <tr><td colspan="8" style="color:var(--muted);">Loading domain matrix...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
        <div>
          <div class="card-header" style="background:rgba(24,34,52,0.3);">
            <h3 class="card-title" style="font-size:0.88rem;">Top All-Traffic Requests by Return Code & Classification</h3>
          </div>
          <div class="table-wrap" style="max-height:390px;">
            <table>
              <thead>
                <tr>
                  <th style="text-align:right;">Hits</th>
                  <th>Status</th>
                  <th>Method</th>
                  <th>Host + Path</th>
                  <th>Class</th>
                  <th style="text-align:right;">Override</th>
                </tr>
              </thead>
              <tbody id="all-traffic-tbody">
                <tr><td colspan="6" style="color:var(--muted);">Loading all traffic rows...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </section>

    <!-- KV Rule Store Editor -->
    <section class="card">
      <div class="card-header">
        <div>
          <h2 class="card-title">KV Honeypot Rule Editor (<code>config:rules</code> in <code>SECURITY_BANS</code>)</h2>
          <div style="font-size:0.78rem;color:var(--muted);margin-top:0.15rem;">
            Override or extend built-in honeypot rules in KV without redeploying code. Enter one path segment per line (e.g. <code>/my-trap</code>).
          </div>
        </div>
        <div style="display:flex;align-items:center;gap:0.65rem;">
          <span id="rules-save-status" style="font-size:0.8rem;color:var(--muted);"></span>
          <button class="emerald" id="save-rules-btn">Save Rules to KV Store</button>
        </div>
      </div>
      <div class="grid-4">
        <div class="rule-col">
          <label style="color:#fda4af;">Custom Strong Trap Segments (403 + 24h Ban)</label>
          <div class="hint">Any request matching these segments bans the client IP for 24h across all domains.</div>
          <textarea id="rules-strong" placeholder="/custom-exploit&#10;/secret-admin.php"></textarea>
        </div>
        <div class="rule-col">
          <label style="color:#fcd34d;">Custom Weak Segments (403 Refuse Only, No Ban)</label>
          <div class="hint">Refuses the request with 403 Forbidden without adding the IP to the 24h ban table.</div>
          <textarea id="rules-weak" placeholder="/legacy-debug&#10;/old-api"></textarea>
        </div>
        <div class="rule-col">
          <label style="color:#6ee7b7;">Custom Safe / Allowlisted Paths (Never Block/Ban)</label>
          <div class="hint">Exempts matching paths even if they would otherwise trigger a built-in rule.</div>
          <textarea id="rules-allow" placeholder="/wp-json/custom-webhook&#10;/metrics-public"></textarea>
        </div>
        <div class="rule-col">
          <label style="color:var(--muted);">Disabled Built-in Segments (Click chip below or type)</label>
          <div class="hint">Built-in segments listed here are bypassed during path classification.</div>
          <textarea id="rules-disabled" placeholder="/metrics"></textarea>
        </div>
      </div>
      <details>
        <summary style="padding:0.65rem 1.25rem;cursor:pointer;font-size:0.82rem;color:var(--accent);border-top:1px solid var(--border);background:var(--panel-alt);">
          View / Toggle All Built-in Strong & Weak Segments (Click any chip to toggle Disabled state)
        </summary>
        <div class="builtin-chips" id="builtin-chips-container"></div>
      </details>
      <div class="tester-box">
        <span style="font-size:0.8rem;color:var(--muted);font-weight:600;">Live Classifier Test (Includes KV Overrides):</span>
        <input type="text" id="test-path-input" placeholder="/.cursor/mcp.json" style="flex:1;min-width:220px;">
        <button id="test-path-btn">Test Path</button>
        <span id="test-path-result" class="mono"></span>
      </div>
    </section>

    <section class="grid-2">
      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Active 24-Hour Banned IPs in KV</h2>
          <div style="display:flex;gap:0.4rem;">
            <input type="text" id="manual-ban-ip" placeholder="IP to ban..." style="width:140px;padding:0.3rem 0.5rem;">
            <button id="manual-ban-btn" class="danger">Ban IP</button>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>IP Address</th>
                <th>TTL Left</th>
                <th>Trigger Path</th>
                <th style="text-align:right;">Action</th>
              </tr>
            </thead>
            <tbody id="active-bans-tbody">
              <tr><td colspan="4" style="color:var(--muted);">Loading KV bans...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Active Bans Grouped by Trigger Path</h2>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th style="text-align:right;">Banned IPs</th>
                <th>Trigger Path</th>
                <th style="text-align:right;">Quick Override</th>
              </tr>
            </thead>
            <tbody id="active-paths-tbody">
              <tr><td colspan="3" style="color:var(--muted);">Loading...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <section class="grid-2">
      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Most-Seen Honeypot Trap Paths (All Cloudflare Zones)</h2>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th style="text-align:right;">Total Hits</th>
                <th style="text-align:right;">403 Blocks</th>
                <th>Return Codes</th>
                <th>Signal</th>
                <th style="text-align:right;">Zones</th>
                <th>Trap Path</th>
                <th style="text-align:right;">Rule Override</th>
              </tr>
            </thead>
            <tbody id="top-paths-tbody">
              <tr><td colspan="7" style="color:var(--muted);">Loading Cloudflare GraphQL telemetry...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Uncaught 4xx/5xx Probe Candidates (Promote in 1 Click)</h2>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th style="text-align:right;">Hits</th>
                <th>Codes</th>
                <th style="text-align:right;">Zones</th>
                <th>Path</th>
                <th style="text-align:right;">Add to KV Store</th>
              </tr>
            </thead>
            <tbody id="uncaught-paths-tbody">
              <tr><td colspan="5" style="color:var(--muted);">Loading uncaught 4xx/5xx paths...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>
  </main>

  <script>
    let currentData = null;

    function formatTtl(ms) {
      if (ms <= 0) return 'expired';
      const mins = Math.round(ms / 60000);
      const h = Math.floor(mins / 60);
      const m = mins % 60;
      return h > 0 ? h + 'h ' + String(m).padStart(2, '0') + 'm' : m + 'm';
    }

    function escapeHtml(str) {
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    function statusPillClass(code) {
      const n = Number(code);
      if (n >= 200 && n < 300) return 'pill-2xx';
      if (n >= 300 && n < 400) return 'pill-3xx';
      if (n === 403) return 'pill-403';
      if (n === 404) return 'pill-404';
      return 'pill-5xx';
    }

    function matchesStatusFilter(code, filterVal) {
      if (!filterVal) return true;
      const n = Number(code);
      if (filterVal === '2xx') return n >= 200 && n < 300;
      if (filterVal === '3xx') return n >= 300 && n < 400;
      if (filterVal === '403') return n === 403;
      if (filterVal === '404') return n === 404;
      if (filterVal === '5xx') return n >= 500;
      return String(n) === filterVal;
    }

    function getLines(id) {
      return document
        .getElementById(id)
        .value.split(/\\r?\\n/)
        .map((s) => s.trim())
        .filter(Boolean);
    }

    function setLines(id, arr) {
      document.getElementById(id).value = (arr || []).join('\\n');
    }

    function addLineToTextarea(id, pathValue) {
      const lines = new Set(getLines(id));
      lines.add(pathValue);
      setLines(id, [...lines]);
    }

    function renderBuiltinChips() {
      if (!currentData || !currentData.builtinRules) return;
      const disabledSet = new Set(getLines('rules-disabled').map((s) => s.toLowerCase()));
      const allBuiltin = [
        ...currentData.builtinRules.strongSegments.map((s) => ({ s, type: 'strong' })),
        ...currentData.builtinRules.weakSegments.map((s) => ({ s, type: 'weak' }))
      ];
      const container = document.getElementById('builtin-chips-container');
      container.innerHTML = allBuiltin
        .map(({ s, type }) => {
          const isDis = disabledSet.has(s.toLowerCase());
          return \`<span class="chip \${isDis ? 'disabled' : ''}" data-chip="\${escapeHtml(s)}" title="Built-in \${type} segment. Click to \${isDis ? 're-enable' : 'disable'}">\${escapeHtml(s)}</span>\`;
        })
        .join('');
    }

    function renderAll() {
      if (!currentData) return;
      const filter = (document.getElementById('path-filter').value || '').trim().toLowerCase();
      const statusFilter = document.getElementById('status-filter').value || '';
      const now = Date.now();

      const customCount =
        (currentData.customRules?.strongSegments?.length || 0) +
        (currentData.customRules?.weakSegments?.length || 0) +
        (currentData.customRules?.allowPaths?.length || 0);

      const tel = currentData.telemetry;
      document.getElementById('kpi-days-label-0').textContent = tel.days + 'd';
      document.getElementById('kpi-days-label').textContent = tel.days + 'd';
      document.getElementById('kpi-days-label-2').textContent = tel.days + 'd';
      document.getElementById('kpi-total-reqs').textContent = (tel.totalRequests || 0).toLocaleString();
      document.getElementById('kpi-active-bans').textContent = currentData.activeBans.length.toLocaleString();
      document.getElementById('kpi-trap-hits').textContent = (tel.totalTrapHits || 0).toLocaleString();
      document.getElementById('kpi-403-blocks').textContent = (tel.total403Blocks || 0).toLocaleString();
      document.getElementById('kpi-unique-paths').textContent = (tel.uniqueTrapPaths || 0).toLocaleString();
      document.getElementById('kpi-rules-count').textContent =
        currentData.rulesCount.strongSegments + ' built-in + ' + customCount + ' KV custom overrides';

      if (tel.error) {
        document.getElementById('telemetry-updated').textContent = tel.error;
      } else if (tel.generatedAt) {
        document.getElementById('telemetry-updated').textContent =
          'Updated ' + new Date(tel.generatedAt).toLocaleTimeString();
      }

      // Status strip
      const totalReqs = Math.max(1, tel.totalRequests || 1);
      const statusStrip = document.getElementById('status-strip');
      statusStrip.innerHTML = (tel.statusSummary || [])
        .map((s) => {
          const pct = ((s.count / totalReqs) * 100).toFixed(1);
          return \`<div class="status-badge" data-status-code="\${s.status}" title="Click to filter by HTTP \${s.status}">
            <span class="pill \${statusPillClass(s.status)}">HTTP \${s.status}</span>
            <strong>\${s.count.toLocaleString()}</strong>
            <span style="color:var(--muted);">(\${pct}%)</span>
          </div>\`;
        })
        .join('');

      // Domain matrix
      const domainRows = (tel.domainMatrix || []).filter(
        (d) => !filter || d.zone.toLowerCase().includes(filter)
      );
      const dmTbody = document.getElementById('domain-matrix-tbody');
      dmTbody.innerHTML = domainRows
        .map(
          (d) => \`<tr style="cursor:pointer;" data-filter-domain="\${escapeHtml(d.zone)}" title="Click to filter by \${escapeHtml(d.zone)}">
            <td class="mono" style="font-weight:600;">\${escapeHtml(d.zone)}</td>
            <td class="num" style="font-weight:700;">\${d.total.toLocaleString()}</td>
            <td class="num" style="color:#6ee7b7;">\${d.s2xx.toLocaleString()}</td>
            <td class="num" style="color:#7dd3fc;">\${d.s3xx.toLocaleString()}</td>
            <td class="num" style="color:#fda4af;font-weight:600;">\${d.s403.toLocaleString()}</td>
            <td class="num" style="color:#fcd34d;">\${d.s404.toLocaleString()}</td>
            <td class="num" style="color:\${d.s5xx > 0 ? '#fda4af' : 'var(--muted)'};">\${d.s5xx.toLocaleString()}</td>
            <td class="num" style="font-weight:600;">\${d.trapHits.toLocaleString()}</td>
          </tr>\`
        )
        .join('');

      // All-traffic rows
      const trafficRows = (tel.allTrafficRows || []).filter((r) => {
        if (!matchesStatusFilter(r.status, statusFilter)) return false;
        if (!filter) return true;
        return (
          r.host.toLowerCase().includes(filter) ||
          r.zone.toLowerCase().includes(filter) ||
          r.path.toLowerCase().includes(filter) ||
          String(r.status).includes(filter)
        );
      });
      const allTrafficTbody = document.getElementById('all-traffic-tbody');
      if (trafficRows.length === 0) {
        allTrafficTbody.innerHTML = '<tr><td colspan="6" style="color:var(--muted);">No matching traffic rows.</td></tr>';
      } else {
        allTrafficTbody.innerHTML = trafficRows
          .slice(0, 150)
          .map((r) => {
            const clsPill =
              r.classification === 'strong'
                ? '<span class="pill pill-strong">strong</span>'
                : r.classification === 'weak'
                ? '<span class="pill pill-weak">weak</span>'
                : '<span class="pill pill-clean">clean</span>';
            return \`<tr>
              <td class="num" style="font-weight:700;">\${r.count.toLocaleString()}x</td>
              <td><span class="pill \${statusPillClass(r.status)}">\${r.status}</span></td>
              <td class="mono">\${escapeHtml(r.method)}</td>
              <td class="mono"><span style="color:var(--muted);">\${escapeHtml(r.host)}</span>\${escapeHtml(r.path)}</td>
              <td>\${clsPill}</td>
              <td style="text-align:right;white-space:nowrap;">
                \${r.classification !== 'strong' ? \`<button class="tiny danger" data-promote-strong="\${escapeHtml(r.path)}">+Strong</button>\` : ''}
                \${r.classification !== 'clean' ? \`<button class="tiny" data-promote-allow="\${escapeHtml(r.path)}">Allow</button>\` : ''}
              </td>
            </tr>\`;
          })
          .join('');
      }

      // 1. Active bans table
      const filteredBans = currentData.activeBans.filter(
        (b) => !filter || b.ip.toLowerCase().includes(filter) || b.path.toLowerCase().includes(filter)
      );
      const bansTbody = document.getElementById('active-bans-tbody');
      if (filteredBans.length === 0) {
        bansTbody.innerHTML = '<tr><td colspan="4" style="color:var(--muted);">No matching active bans.</td></tr>';
      } else {
        bansTbody.innerHTML = filteredBans
          .map(
            (b) => \`<tr>
              <td class="mono">\${escapeHtml(b.ip)}</td>
              <td class="num">\${formatTtl((b.expiresAt || 0) - now)}</td>
              <td class="mono">\${escapeHtml(b.path)}</td>
              <td style="text-align:right;">
                <button class="danger" data-unban="\${escapeHtml(b.ip)}">Unban</button>
              </td>
            </tr>\`
          )
          .join('');
      }

      // 2. Active bans grouped by path
      const byPath = new Map();
      for (const b of filteredBans) {
        byPath.set(b.path, (byPath.get(b.path) || 0) + 1);
      }
      const sortedByPath = [...byPath.entries()].sort((a, b) => b[1] - a[1]);
      const activePathsTbody = document.getElementById('active-paths-tbody');
      activePathsTbody.innerHTML = sortedByPath
        .map(
          ([p, cnt]) => \`<tr>
            <td class="num" style="font-weight:700;">\${cnt}</td>
            <td class="mono">\${escapeHtml(p)}</td>
            <td style="text-align:right;">
              <button class="tiny" data-promote-allow="\${escapeHtml(p)}">Allow Path</button>
            </td>
          </tr>\`
        )
        .join('');

      // 3. Top paths table
      const filteredPaths = (tel.paths || []).filter(
        (p) => !filter || p.path.toLowerCase().includes(filter)
      );
      const topPathsTbody = document.getElementById('top-paths-tbody');
      if (filteredPaths.length === 0) {
        topPathsTbody.innerHTML = '<tr><td colspan="7" style="color:var(--muted);">No matching paths.</td></tr>';
      } else {
        topPathsTbody.innerHTML = filteredPaths
          .map(
            (p) => \`<tr>
              <td class="num" style="font-weight:700;">\${p.count.toLocaleString()}x</td>
              <td class="num">\${p.blocked403.toLocaleString()}x</td>
              <td class="mono">\${(p.statuses || []).join(', ')}</td>
              <td><span class="pill \${p.type === 'strong' ? 'pill-strong' : 'pill-weak'}">\${escapeHtml(p.type)}</span></td>
              <td class="num" title="\${escapeHtml((p.zones || []).join(', '))}">\${p.zoneCount}</td>
              <td class="mono">\${escapeHtml(p.path)}</td>
              <td style="text-align:right;white-space:nowrap;">
                \${p.type === 'weak' ? \`<button class="tiny danger" data-promote-strong="\${escapeHtml(p.path)}">+Strong</button>\` : ''}
                <button class="tiny" data-promote-allow="\${escapeHtml(p.path)}">Allow</button>
              </td>
            </tr>\`
          )
          .join('');
      }

      // 4. Uncaught 4xx/5xx candidates
      const filteredUncaught = (tel.uncaughtPaths || []).filter(
        (p) => !filter || p.path.toLowerCase().includes(filter)
      );
      const uncaughtTbody = document.getElementById('uncaught-paths-tbody');
      if (filteredUncaught.length === 0) {
        uncaughtTbody.innerHTML = '<tr><td colspan="5" style="color:var(--muted);">No uncaught 4xx/5xx probe candidates.</td></tr>';
      } else {
        uncaughtTbody.innerHTML = filteredUncaught
          .map(
            (p) => \`<tr>
              <td class="num" style="font-weight:700;">\${p.count.toLocaleString()}x</td>
              <td class="mono">\${(p.statuses || []).join(', ')}</td>
              <td class="num">\${p.zoneCount}</td>
              <td class="mono">\${escapeHtml(p.path)}</td>
              <td style="text-align:right;white-space:nowrap;">
                <button class="tiny danger" data-promote-strong="\${escapeHtml(p.path)}">+Strong</button>
                <button class="tiny" data-promote-weak="\${escapeHtml(p.path)}">+Weak</button>
              </td>
            </tr>\`
          )
          .join('');
      }
    }

    async function saveRulesNow() {
      const btn = document.getElementById('save-rules-btn');
      const statusEl = document.getElementById('rules-save-status');
      btn.textContent = 'Saving...';
      const payload = {
        strongSegments: getLines('rules-strong'),
        weakSegments: getLines('rules-weak'),
        allowPaths: getLines('rules-allow'),
        disabledSegments: getLines('rules-disabled')
      };
      const res = await fetch('/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const saved = await res.json();
      btn.textContent = 'Save Rules to KV Store';
      statusEl.textContent = 'Saved to KV at ' + new Date(saved.rules.updatedAt).toLocaleTimeString();
      statusEl.style.color = '#10b981';
      await loadStats(false);
    }

    async function loadStats(populateEditor = true) {
      const days = document.getElementById('days-select').value || '7';
      const btn = document.getElementById('refresh-btn');
      btn.textContent = 'Loading...';
      try {
        const res = await fetch('/api/stats?days=' + encodeURIComponent(days));
        currentData = await res.json();
        if (populateEditor && currentData.customRules) {
          setLines('rules-strong', currentData.customRules.strongSegments);
          setLines('rules-weak', currentData.customRules.weakSegments);
          setLines('rules-allow', currentData.customRules.allowPaths);
          setLines('rules-disabled', currentData.customRules.disabledSegments);
          if (currentData.customRules.updatedAt) {
            document.getElementById('rules-save-status').textContent =
              'Last saved: ' + new Date(currentData.customRules.updatedAt).toLocaleString();
          }
        }
        renderBuiltinChips();
        renderAll();
      } finally {
        btn.textContent = 'Refresh Live Data';
      }
    }

    document.getElementById('refresh-btn').addEventListener('click', () => loadStats(true));
    document.getElementById('days-select').addEventListener('change', () => loadStats(false));
    document.getElementById('status-filter').addEventListener('change', renderAll);
    document.getElementById('path-filter').addEventListener('input', renderAll);
    document.getElementById('save-rules-btn').addEventListener('click', saveRulesNow);

    document.getElementById('builtin-chips-container').addEventListener('click', (e) => {
      const chip = e.target.closest('[data-chip]');
      if (!chip) return;
      const seg = chip.getAttribute('data-chip');
      const current = new Set(getLines('rules-disabled'));
      if (current.has(seg)) {
        current.delete(seg);
      } else {
        current.add(seg);
      }
      setLines('rules-disabled', [...current]);
      renderBuiltinChips();
    });

    document.body.addEventListener('click', async (e) => {
      const statusBadge = e.target.closest('[data-status-code]');
      if (statusBadge) {
        const code = statusBadge.getAttribute('data-status-code');
        const filterInput = document.getElementById('path-filter');
        filterInput.value = filterInput.value === code ? '' : code;
        renderAll();
        return;
      }
      const domainRow = e.target.closest('[data-filter-domain]');
      if (domainRow) {
        const dom = domainRow.getAttribute('data-filter-domain');
        const filterInput = document.getElementById('path-filter');
        filterInput.value = filterInput.value === dom ? '' : dom;
        renderAll();
        return;
      }
      const strongBtn = e.target.closest('[data-promote-strong]');
      if (strongBtn) {
        addLineToTextarea('rules-strong', strongBtn.getAttribute('data-promote-strong'));
        await saveRulesNow();
        return;
      }
      const weakBtn = e.target.closest('[data-promote-weak]');
      if (weakBtn) {
        addLineToTextarea('rules-weak', weakBtn.getAttribute('data-promote-weak'));
        await saveRulesNow();
        return;
      }
      const allowBtn = e.target.closest('[data-promote-allow]');
      if (allowBtn) {
        addLineToTextarea('rules-allow', allowBtn.getAttribute('data-promote-allow'));
        await saveRulesNow();
        return;
      }
      const unbanBtn = e.target.closest('[data-unban]');
      if (unbanBtn) {
        const ip = unbanBtn.getAttribute('data-unban');
        unbanBtn.textContent = '...';
        await fetch('/api/unban', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip })
        });
        await loadStats(false);
      }
    });

    document.getElementById('manual-ban-btn').addEventListener('click', async () => {
      const input = document.getElementById('manual-ban-ip');
      const ip = input.value.trim();
      if (!ip) return;
      await fetch('/api/ban', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, path: '/manual-dashboard-ban' })
      });
      input.value = '';
      await loadStats(false);
    });

    document.getElementById('test-path-btn').addEventListener('click', async () => {
      const pathVal = document.getElementById('test-path-input').value.trim() || '/';
      const res = await fetch('/api/classify?path=' + encodeURIComponent(pathVal));
      const data = await res.json();
      const out = document.getElementById('test-path-result');
      out.textContent = data.classification ? 'TRAP (' + data.classification.toUpperCase() + ')' : 'CLEAN (null)';
      out.style.color = data.classification === 'strong' ? '#fda4af' : data.classification === 'weak' ? '#fcd34d' : '#10b981';
    });

    loadStats(true);
  </script>
</body>
</html>`;
}

export default {
    async fetch(request, env = {}) {
        const url = new URL(request.url);
        const path = url.pathname;

        const securityHeaders = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'no-referrer',
            'X-Robots-Tag': 'noindex, nofollow',
            'Cache-Control': 'no-store'
        };

        if (path === '/__health') {
            return new Response(JSON.stringify({ ok: true, service: 'cf-hp-stats' }), {
                status: 200,
                headers: { ...securityHeaders, 'Content-Type': 'application/json; charset=utf-8' }
            });
        }

        if (path === '/api/classify') {
            const testPath = url.searchParams.get('path') || '/';
            const customRules = await getCustomRules(env);
            return new Response(
                JSON.stringify({
                    path: testPath,
                    classification: classifyScannerPath(testPath, { customRules })
                }),
                {
                    status: 200,
                    headers: { ...securityHeaders, 'Content-Type': 'application/json; charset=utf-8' }
                }
            );
        }

        if (path === '/api/rules') {
            if (request.method === 'GET') {
                const customRules = await getCustomRules(env);
                return new Response(
                    JSON.stringify({
                        customRules,
                        builtinRules: {
                            strongSegments: SCANNER_SEGMENTS,
                            weakSegments: WEAK_SCANNER_SEGMENTS
                        }
                    }),
                    {
                        status: 200,
                        headers: { ...securityHeaders, 'Content-Type': 'application/json; charset=utf-8' }
                    }
                );
            }
            if (request.method === 'POST') {
                const body = await request.json();
                const saved = await saveCustomRules(body, env);
                cachedZoneStats.expiresAt = 0;
                return new Response(JSON.stringify({ ok: true, rules: saved }), {
                    status: 200,
                    headers: { ...securityHeaders, 'Content-Type': 'application/json; charset=utf-8' }
                });
            }
        }

        if (path === '/api/unban' && request.method === 'POST') {
            const body = await request.json();
            const ip = (body.ip || '').trim().toLowerCase();
            if (ip && env.SECURITY_BANS) {
                await env.SECURITY_BANS.delete(`ban:${ip}`);
            }
            return new Response(JSON.stringify({ ok: true, unbanned: ip }), {
                status: 200,
                headers: { ...securityHeaders, 'Content-Type': 'application/json; charset=utf-8' }
            });
        }

        if (path === '/api/ban' && request.method === 'POST') {
            const body = await request.json();
            const ip = (body.ip || '').trim().toLowerCase();
            const reasonPath = body.path || '/manual-dashboard-ban';
            const now = Date.now();
            if (ip && env.SECURITY_BANS) {
                await env.SECURITY_BANS.put(
                    `ban:${ip}`,
                    JSON.stringify({
                        ip,
                        path: reasonPath,
                        bannedAt: now,
                        expiresAt: now + BAN_TTL_MS
                    }),
                    { expirationTtl: BAN_TTL_SECONDS }
                );
            }
            return new Response(JSON.stringify({ ok: true, banned: ip }), {
                status: 200,
                headers: { ...securityHeaders, 'Content-Type': 'application/json; charset=utf-8' }
            });
        }

        if (path === '/api/stats') {
            const days = Math.max(1, Math.min(30, Number(url.searchParams.get('days')) || 7));
            const token = env.CF_ANALYTICS_TOKEN || '';
            const customRules = await getCustomRules(env);
            const [activeBans, telemetry] = await Promise.all([
                listActiveBansFromKv(env),
                fetchZoneTrapTelemetry(token, days, customRules)
            ]);

            return new Response(
                JSON.stringify({
                    activeBans,
                    telemetry,
                    customRules,
                    builtinRules: {
                        strongSegments: SCANNER_SEGMENTS,
                        weakSegments: WEAK_SCANNER_SEGMENTS
                    },
                    rulesCount: {
                        strongSegments: SCANNER_SEGMENTS.length,
                        weakSegments: WEAK_SCANNER_SEGMENTS.length
                    }
                }),
                {
                    status: 200,
                    headers: { ...securityHeaders, 'Content-Type': 'application/json; charset=utf-8' }
                }
            );
        }

        return new Response(renderDashboardHtml(), {
            status: 200,
            headers: { ...securityHeaders, 'Content-Type': 'text/html; charset=utf-8' }
        });
    }
};
