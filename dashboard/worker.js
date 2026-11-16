/**
 * Cloudflare Edge Honeypot Telemetry Dashboard Worker (`cf-hp-stats.emerald-glen.com`)
 *
 * Protected behind Cloudflare Access (`*.emerald-glen.com`).
 * - Directly reads/manages active 24h bans from `env.SECURITY_BANS` KV binding
 * - Queries multi-day HTTP trap telemetry across all 19 Cloudflare zones via `env.CF_ANALYTICS_TOKEN`
 */

import {
    BAN_TTL_MS,
    BAN_TTL_SECONDS,
    SCANNER_SEGMENTS,
    WEAK_SCANNER_SEGMENTS,
    classifyScannerPath
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

async function fetchZoneTrapTelemetry(token, days = 7) {
    if (!token) {
        return {
            configured: false,
            error: 'CF_ANALYTICS_TOKEN secret not configured yet.',
            totalTrapHits: 0,
            total403Blocks: 0,
            uniqueTrapPaths: 0,
            zones: [],
            paths: []
        };
    }

    const now = Date.now();
    const cacheKey = `${days}`;
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
            totalTrapHits: 0,
            total403Blocks: 0,
            uniqueTrapPaths: 0,
            zones: [],
            paths: []
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
          httpRequestsAdaptiveGroups(
            limit: 500
            filter: {datetime_geq: $start, datetime_leq: $end}
            orderBy: [count_DESC]
          ) {
            count
            dimensions {
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
            const groups = res?.data?.viewer?.zones?.[0]?.httpRequestsAdaptiveGroups || [];
            for (const g of groups) {
                const p = g.dimensions.clientRequestPath;
                const status = g.dimensions.edgeResponseStatus;
                const cnt = g.count;

                if (status === 403) {
                    total403Blocks += cnt;
                }

                const classification = classifyScannerPath(p);
                if (classification) {
                    totalTrapHits += cnt;
                    zoneTrapTotals.set(z.name, (zoneTrapTotals.get(z.name) || 0) + cnt);

                    const existing = pathStats.get(p) || {
                        path: p,
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
            // Ignore single-zone failure
        }
    });

    const sortedPaths = [...pathStats.values()]
        .map((item) => ({
            path: item.path,
            count: item.count,
            blocked403: item.blocked403,
            type: item.type,
            zoneCount: item.zones.size,
            zones: [...item.zones].sort()
        }))
        .sort((a, b) => b.count - a.count);

    const sortedZones = [...zoneTrapTotals.entries()]
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count);

    const data = {
        configured: true,
        error: null,
        days,
        generatedAt: new Date(now).toISOString(),
        totalTrapHits,
        total403Blocks,
        uniqueTrapPaths: sortedPaths.length,
        zones: sortedZones,
        paths: sortedPaths.slice(0, 150)
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
  <title>Cloudflare Edge Honeypot Telemetry | Emerald Glen</title>
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
      background: rgba(19, 27, 41, 0.9);
      backdrop-filter: blur(10px);
      position: sticky;
      top: 0;
      z-index: 10;
      padding: 1rem 1.5rem;
    }
    .header-inner {
      max-width: 1440px;
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
    button, select, input {
      background: var(--panel-alt);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.45rem 0.8rem;
      font-size: 0.85rem;
      font-family: inherit;
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
    button.danger {
      background: rgba(244, 63, 94, 0.14);
      border-color: rgba(244, 63, 94, 0.4);
      color: #fda4af;
      padding: 0.25rem 0.55rem;
      font-size: 0.75rem;
    }
    main {
      max-width: 1440px;
      margin: 1.5rem auto;
      padding: 0 1.5rem 3rem;
      display: grid;
      gap: 1.5rem;
    }
    .kpis {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
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
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .kpi-val {
      font-size: 1.9rem;
      font-weight: 700;
      font-family: var(--mono);
      margin-top: 0.25rem;
    }
    .kpi-sub {
      color: var(--muted);
      font-size: 0.78rem;
      margin-top: 0.25rem;
    }
    .grid-2 {
      display: grid;
      grid-template-columns: 1.15fr 1fr;
      gap: 1.5rem;
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
      max-height: 540px;
      overflow-y: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.84rem;
    }
    th, td {
      padding: 0.55rem 0.9rem;
      text-align: left;
      border-bottom: 1px solid rgba(37, 51, 77, 0.6);
    }
    th {
      background: var(--panel-alt);
      color: var(--muted);
      font-weight: 600;
      font-size: 0.75rem;
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
      font-size: 0.8rem;
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
    .pill-strong {
      background: rgba(244, 63, 94, 0.16);
      color: #fda4af;
      border: 1px solid rgba(244, 63, 94, 0.35);
    }
    .pill-weak {
      background: rgba(245, 158, 11, 0.16);
      color: #fcd34d;
      border: 1px solid rgba(245, 158, 11, 0.35);
    }
    .bar-row {
      display: grid;
      grid-template-columns: 210px 1fr 75px;
      align-items: center;
      gap: 0.75rem;
      padding: 0.45rem 1.25rem;
      border-bottom: 1px solid rgba(37, 51, 77, 0.45);
      font-size: 0.83rem;
    }
    .bar-track {
      height: 8px;
      background: var(--panel-alt);
      border-radius: 999px;
      overflow: hidden;
    }
    .bar-fill {
      height: 100%;
      background: linear-gradient(90deg, var(--accent), var(--emerald));
      border-radius: 999px;
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
  </style>
</head>
<body>
  <header>
    <div class="header-inner">
      <div class="brand">
        <span class="badge-live">Edge KV Mesh Active</span>
        <h1>Cloudflare Edge Honeypot Telemetry</h1>
      </div>
      <div class="controls">
        <label for="days-select" style="color:var(--muted);font-size:0.82rem;">Window:</label>
        <select id="days-select">
          <option value="1">Last 24 Hours</option>
          <option value="7" selected>Last 7 Days</option>
          <option value="14">Last 14 Days</option>
        </select>
        <input type="search" id="path-filter" placeholder="Filter paths or IPs..." style="min-width:220px;">
        <button class="primary" id="refresh-btn">Refresh Live Data</button>
      </div>
    </div>
  </header>

  <main>
    <section class="kpis">
      <div class="kpi">
        <div class="kpi-label">Active 24h KV Bans</div>
        <div class="kpi-val" id="kpi-active-bans">--</div>
        <div class="kpi-sub">Shared across all connected domains</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Total Trap Hits (<span id="kpi-days-label">7d</span>)</div>
        <div class="kpi-val" id="kpi-trap-hits">--</div>
        <div class="kpi-sub">Requests matching honeypot signatures</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Total 403 Edge Blocks (<span id="kpi-days-label-2">7d</span>)</div>
        <div class="kpi-val" id="kpi-403-blocks">--</div>
        <div class="kpi-sub">Includes repeat hits from banned IPs</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Unique Attack Paths Seen</div>
        <div class="kpi-val" id="kpi-unique-paths">--</div>
        <div class="kpi-sub" id="kpi-rules-count">-- configured rules</div>
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
              </tr>
            </thead>
            <tbody id="active-paths-tbody">
              <tr><td colspan="2" style="color:var(--muted);">Loading...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <section class="grid-2">
      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Most-Seen Honeypot Trap Paths (All Cloudflare Zones)</h2>
          <span id="telemetry-updated" style="color:var(--muted);font-size:0.78rem;"></span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th style="text-align:right;">Total Hits</th>
                <th style="text-align:right;">403 Blocks</th>
                <th>Signal</th>
                <th style="text-align:right;">Zones</th>
                <th>Trap Path</th>
              </tr>
            </thead>
            <tbody id="top-paths-tbody">
              <tr><td colspan="5" style="color:var(--muted);">Loading Cloudflare GraphQL telemetry...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Honeypot Trap Hits by Domain Zone</h2>
        </div>
        <div id="zones-bars" style="padding: 0.6rem 0; max-height: 460px; overflow-y: auto;">
          <div style="padding:1rem 1.25rem;color:var(--muted);">Loading zone breakdown...</div>
        </div>
        <div class="tester-box">
          <span style="font-size:0.8rem;color:var(--muted);font-weight:600;">Path Classifier Test:</span>
          <input type="text" id="test-path-input" placeholder="/.cursor/mcp.json" style="flex:1;min-width:180px;">
          <button id="test-path-btn">Test Path</button>
          <span id="test-path-result" class="mono"></span>
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

    function renderAll() {
      if (!currentData) return;
      const filter = (document.getElementById('path-filter').value || '').trim().toLowerCase();
      const now = Date.now();

      document.getElementById('kpi-active-bans').textContent = currentData.activeBans.length.toLocaleString();
      document.getElementById('kpi-rules-count').textContent =
        currentData.rulesCount.strongSegments + ' strong segments + dotfile/ext regexes';

      const tel = currentData.telemetry;
      document.getElementById('kpi-days-label').textContent = tel.days + 'd';
      document.getElementById('kpi-days-label-2').textContent = tel.days + 'd';
      document.getElementById('kpi-trap-hits').textContent = (tel.totalTrapHits || 0).toLocaleString();
      document.getElementById('kpi-403-blocks').textContent = (tel.total403Blocks || 0).toLocaleString();
      document.getElementById('kpi-unique-paths').textContent = (tel.uniqueTrapPaths || 0).toLocaleString();

      if (tel.error) {
        document.getElementById('telemetry-updated').textContent = tel.error;
      } else if (tel.generatedAt) {
        document.getElementById('telemetry-updated').textContent =
          'Updated ' + new Date(tel.generatedAt).toLocaleTimeString();
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
          </tr>\`
        )
        .join('');

      // 3. Top paths table
      const filteredPaths = (tel.paths || []).filter(
        (p) => !filter || p.path.toLowerCase().includes(filter)
      );
      const topPathsTbody = document.getElementById('top-paths-tbody');
      if (filteredPaths.length === 0) {
        topPathsTbody.innerHTML = '<tr><td colspan="5" style="color:var(--muted);">No matching paths.</td></tr>';
      } else {
        topPathsTbody.innerHTML = filteredPaths
          .map(
            (p) => \`<tr>
              <td class="num" style="font-weight:700;">\${p.count.toLocaleString()}x</td>
              <td class="num">\${p.blocked403.toLocaleString()}x</td>
              <td><span class="pill \${p.type === 'strong' ? 'pill-strong' : 'pill-weak'}">\${escapeHtml(p.type)}</span></td>
              <td class="num" title="\${escapeHtml((p.zones || []).join(', '))}">\${p.zoneCount}</td>
              <td class="mono">\${escapeHtml(p.path)}</td>
            </tr>\`
          )
          .join('');
      }

      // 4. Zone bars
      const zones = tel.zones || [];
      const maxZone = zones.reduce((m, z) => Math.max(m, z.count), 1);
      const zonesBars = document.getElementById('zones-bars');
      zonesBars.innerHTML = zones
        .map((z) => {
          const pct = Math.max(2, Math.round((z.count / maxZone) * 100));
          return \`<div class="bar-row">
            <div class="mono" style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">\${escapeHtml(z.name)}</div>
            <div class="bar-track"><div class="bar-fill" style="width:\${pct}%"></div></div>
            <div class="num">\${z.count.toLocaleString()}x</div>
          </div>\`;
        })
        .join('');
    }

    async function loadStats() {
      const days = document.getElementById('days-select').value || '7';
      const btn = document.getElementById('refresh-btn');
      btn.textContent = 'Loading...';
      try {
        const res = await fetch('/api/stats?days=' + encodeURIComponent(days));
        currentData = await res.json();
        renderAll();
      } finally {
        btn.textContent = 'Refresh Live Data';
      }
    }

    document.getElementById('refresh-btn').addEventListener('click', loadStats);
    document.getElementById('days-select').addEventListener('change', loadStats);
    document.getElementById('path-filter').addEventListener('input', renderAll);

    document.getElementById('active-bans-tbody').addEventListener('click', async (e) => {
      const btn = e.target.closest('[data-unban]');
      if (!btn) return;
      const ip = btn.getAttribute('data-unban');
      btn.textContent = '...';
      await fetch('/api/unban', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      await loadStats();
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
      await loadStats();
    });

    document.getElementById('test-path-btn').addEventListener('click', async () => {
      const pathVal = document.getElementById('test-path-input').value.trim() || '/';
      const res = await fetch('/api/classify?path=' + encodeURIComponent(pathVal));
      const data = await res.json();
      const out = document.getElementById('test-path-result');
      out.textContent = data.classification ? 'TRAP (' + data.classification.toUpperCase() + ')' : 'CLEAN (null)';
      out.style.color = data.classification === 'strong' ? '#fda4af' : data.classification === 'weak' ? '#fcd34d' : '#10b981';
    });

    loadStats();
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
            return new Response(
                JSON.stringify({
                    path: testPath,
                    classification: classifyScannerPath(testPath)
                }),
                {
                    status: 200,
                    headers: { ...securityHeaders, 'Content-Type': 'application/json; charset=utf-8' }
                }
            );
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
            const [activeBans, telemetry] = await Promise.all([
                listActiveBansFromKv(env),
                fetchZoneTrapTelemetry(token, days)
            ]);

            return new Response(
                JSON.stringify({
                    activeBans,
                    telemetry,
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
