/**
 * Cloudflare Edge Honeypot Telemetry, All-Traffic Return Code Matrix, Attack Origin Geo & Rule Editor Dashboard Worker
 * (`cf-hp-stats.emerald-glen.com`)
 *
 * Protected behind Cloudflare Access (`*.emerald-glen.com`).
 * - Directly reads/manages active 24h bans from `env.SECURITY_BANS` KV binding (including Country, City, ASN/Org, Target Host)
 * - Reads/writes dynamic KV rule overrides (`config:rules` in `env.SECURITY_BANS`)
 * - Queries multi-day HTTP trap telemetry, full status code distribution, and country origin across all 19 Cloudflare zones via `env.CF_ANALYTICS_TOKEN`
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
        host: parsed.host || '',
        country: parsed.country || '',
        city: parsed.city || '',
        region: parsed.region || '',
        asn: parsed.asn || null,
        asOrganization: parsed.asOrganization || '',
        userAgent: parsed.userAgent || '',
        bannedAt: parsed.bannedAt || 0,
        expiresAt: parsed.expiresAt || (k.expiration ? k.expiration * 1000 : 0)
      };
    } catch {
      return {
        key: k.name,
        ip: k.name.replace(/^ban:/, ''),
        path: '(unreadable)',
        host: '',
        country: '',
        city: '',
        region: '',
        asn: null,
        asOrganization: '',
        userAgent: '',
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
      totalAllRequests: 0,
      totalTrapHits: 0,
      total403Blocks: 0,
      uniqueTrapPaths: 0,
      statusTotals: { s2xx: 0, s3xx: 0, s403: 0, s404: 0, s4xxOther: 0, s5xx: 0, byCode: [] },
      domainMatrix: [],
      countries: [],
      zones: [],
      paths: [],
      uncaughtPaths: [],
      allTrafficRows: []
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
      totalAllRequests: 0,
      totalTrapHits: 0,
      total403Blocks: 0,
      uniqueTrapPaths: 0,
      statusTotals: { s2xx: 0, s3xx: 0, s403: 0, s404: 0, s4xxOther: 0, s5xx: 0, byCode: [] },
      domainMatrix: [],
      countries: [],
      zones: [],
      paths: [],
      uncaughtPaths: [],
      allTrafficRows: []
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
          statusGroups: httpRequestsAdaptiveGroups(
            limit: 100
            filter: {datetime_geq: $start, datetime_leq: $end}
            orderBy: [count_DESC]
          ) {
            count
            dimensions {
              edgeResponseStatus
            }
          }
          countryGroups: httpRequestsAdaptiveGroups(
            limit: 150
            filter: {datetime_geq: $start, datetime_leq: $end}
            orderBy: [count_DESC]
          ) {
            count
            dimensions {
              clientCountryName
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
              clientCountryName
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
  const countryStatsMap = new Map();
  const allTrafficMap = new Map();

  let totalAllRequests = 0;
  let totalTrapHits = 0;
  let total403Blocks = 0;
  let s2xx = 0;
  let s3xx = 0;
  let s403 = 0;
  let s404 = 0;
  let s4xxOther = 0;
  let s5xx = 0;

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
      const zoneData = res?.data?.viewer?.zones?.[0] || {};
      const statusGroups = zoneData.statusGroups || [];
      const countryGroups = zoneData.countryGroups || [];
      const pathGroups = zoneData.pathGroups || [];

      const domStat = {
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
        const code = Number(sg.dimensions.edgeResponseStatus) || 0;
        const cnt = Number(sg.count) || 0;
        totalAllRequests += cnt;
        domStat.total += cnt;
        globalStatusCounts.set(code, (globalStatusCounts.get(code) || 0) + cnt);

        if (code >= 200 && code < 300) {
          s2xx += cnt;
          domStat.s2xx += cnt;
        } else if (code >= 300 && code < 400) {
          s3xx += cnt;
          domStat.s3xx += cnt;
        } else if (code === 403) {
          s403 += cnt;
          total403Blocks += cnt;
          domStat.s403 += cnt;
        } else if (code === 404) {
          s404 += cnt;
          domStat.s404 += cnt;
        } else if (code >= 400 && code < 500) {
          s4xxOther += cnt;
          domStat.s4xxOther += cnt;
        } else if (code >= 500) {
          s5xx += cnt;
          domStat.s5xx += cnt;
        }
      }

      for (const cg of countryGroups) {
        const country = cg.dimensions.clientCountryName || 'XX';
        const code = Number(cg.dimensions.edgeResponseStatus) || 0;
        const cnt = Number(cg.count) || 0;
        const cEntry = countryStatsMap.get(country) || {
          country,
          totalRequests: 0,
          blocked403: 0,
          trapHits: 0,
          zones: new Set()
        };
        cEntry.totalRequests += cnt;
        if (code === 403) cEntry.blocked403 += cnt;
        cEntry.zones.add(z.name);
        countryStatsMap.set(country, cEntry);
      }

      for (const g of pathGroups) {
        const p = g.dimensions.clientRequestPath || '/';
        const host = g.dimensions.clientRequestHTTPHost || z.name;
        const method = g.dimensions.clientRequestHTTPMethodName || 'GET';
        const country = g.dimensions.clientCountryName || 'XX';
        const status = Number(g.dimensions.edgeResponseStatus) || 0;
        const cnt = Number(g.count) || 0;

        const classification = classifyScannerPath(p, { customRules });

        // Track in allTrafficMap (grouped by host + method + path + status)
        const trafficKey = `${host}|${method}|${p}|${status}`;
        const existingTraffic = allTrafficMap.get(trafficKey) || {
          zone: z.name,
          host,
          method,
          path: p,
          status,
          count: 0,
          classification: classification || 'clean',
          countries: new Map()
        };
        existingTraffic.count += cnt;
        existingTraffic.countries.set(country, (existingTraffic.countries.get(country) || 0) + cnt);
        allTrafficMap.set(trafficKey, existingTraffic);

        if (classification) {
          totalTrapHits += cnt;
          domStat.trapHits += cnt;
          zoneTrapTotals.set(z.name, (zoneTrapTotals.get(z.name) || 0) + cnt);

          const cEntry = countryStatsMap.get(country) || {
            country,
            totalRequests: 0,
            blocked403: 0,
            trapHits: 0,
            zones: new Set()
          };
          cEntry.trapHits += cnt;
          cEntry.zones.add(z.name);
          countryStatsMap.set(country, cEntry);

          const existing = pathStats.get(p) || {
            path: p,
            count: 0,
            blocked403: 0,
            type: classification,
            zones: new Set(),
            countries: new Map()
          };
          existing.count += cnt;
          if (status === 403) existing.blocked403 += cnt;
          existing.zones.add(z.name);
          existing.countries.set(country, (existing.countries.get(country) || 0) + cnt);
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
            status,
            zones: new Set()
          };
          u.count += cnt;
          u.zones.add(z.name);
          uncaughtStats.set(p, u);
        }
      }

      if (domStat.total > 0 || domStat.trapHits > 0) {
        domainMatrixMap.set(z.name, domStat);
      }
    } catch {
      // Ignore single-zone failure
    }
  });

  const sortedPaths = [...pathStats.values()]
    .map((item) => {
      const topCountries = [...item.countries.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 4)
        .map(([c, n]) => `${c} (${n})`);
      return {
        path: item.path,
        count: item.count,
        blocked403: item.blocked403,
        type: item.type,
        zoneCount: item.zones.size,
        zones: [...item.zones].sort(),
        topCountries
      };
    })
    .sort((a, b) => b.count - a.count);

  const sortedUncaught = [...uncaughtStats.values()]
    .map((item) => ({
      path: item.path,
      count: item.count,
      status: item.status,
      zoneCount: item.zones.size
    }))
    .sort((a, b) => b.count - a.count);

  const sortedZones = [...zoneTrapTotals.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);

  const sortedDomainMatrix = [...domainMatrixMap.values()].sort((a, b) => b.total - a.total);

  const sortedCountries = [...countryStatsMap.values()]
    .map((c) => ({
      country: c.country,
      totalRequests: c.totalRequests,
      blocked403: c.blocked403,
      trapHits: c.trapHits,
      zoneCount: c.zones.size
    }))
    .sort((a, b) => b.trapHits - a.trapHits || b.totalRequests - a.totalRequests);

  const sortedByCode = [...globalStatusCounts.entries()]
    .map(([status, count]) => ({ status, count }))
    .sort((a, b) => b.count - a.count);

  const sortedAllTraffic = [...allTrafficMap.values()]
    .map((item) => {
      const topCountries = [...item.countries.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([c, n]) => (n > 1 ? `${c}(${n})` : c));
      return {
        zone: item.zone,
        host: item.host,
        method: item.method,
        path: item.path,
        status: item.status,
        count: item.count,
        classification: item.classification,
        topCountries
      };
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 400);

  const data = {
    configured: true,
    error: null,
    days,
    generatedAt: new Date(now).toISOString(),
    totalAllRequests,
    totalTrapHits,
    total403Blocks,
    uniqueTrapPaths: sortedPaths.length,
    statusTotals: {
      s2xx,
      s3xx,
      s403,
      s404,
      s4xxOther,
      s5xx,
      byCode: sortedByCode
    },
    domainMatrix: sortedDomainMatrix,
    countries: sortedCountries.slice(0, 50),
    zones: sortedZones,
    paths: sortedPaths.slice(0, 150),
    uncaughtPaths: sortedUncaught.slice(0, 40),
    allTrafficRows: sortedAllTraffic
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
  <title>Cloudflare Edge Honeypot Telemetry & Rule Editor | Emerald Glen</title>
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
      --purple: #a855f7;
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
      max-width: 1540px;
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
      min-height: 115px;
      resize: vertical;
    }
    button {
      cursor: pointer;
      font-weight: 600;
      transition: background 0.15s, border-color 0.15s;
    }
    button:hover {
      background: #223049;
      border-color: var(--accent);
    }
    button.primary {
      background: rgba(56, 189, 248, 0.15);
      border-color: rgba(56, 189, 248, 0.4);
      color: var(--accent);
    }
    button.emerald {
      background: rgba(16, 185, 129, 0.16);
      border-color: rgba(16, 185, 129, 0.45);
      color: #6ee7b7;
    }
    button.danger {
      background: rgba(244, 63, 94, 0.14);
      border-color: rgba(244, 63, 94, 0.4);
      color: #fda4af;
      padding: 0.25rem 0.55rem;
      font-size: 0.76rem;
    }
    button.tiny {
      padding: 0.18rem 0.45rem;
      font-size: 0.72rem;
      border-radius: 4px;
    }
    main {
      max-width: 1540px;
      margin: 1.5rem auto;
      padding: 0 1.5rem 3rem;
      display: flex;
      flex-direction: column;
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
      padding: 1.05rem 1.2rem;
    }
    .kpi-label {
      color: var(--muted);
      font-size: 0.76rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      font-weight: 600;
    }
    .kpi-val {
      font-size: 1.75rem;
      font-weight: 800;
      margin-top: 0.2rem;
      font-family: var(--mono);
    }
    .kpi-sub {
      color: var(--muted);
      font-size: 0.76rem;
      margin-top: 0.2rem;
    }
    .grid-2 {
      display: grid;
      grid-template-columns: 1.15fr 0.85fr;
      gap: 1.5rem;
    }
    .grid-4 {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 1rem;
      padding: 1.1rem 1.25rem;
    }
    @media (max-width: 1120px) {
      .grid-2 { grid-template-columns: 1fr; }
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }
    .card-header {
      padding: 0.9rem 1.25rem;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      background: rgba(24, 34, 52, 0.55);
      flex-wrap: wrap;
    }
    .card-title {
      font-size: 0.95rem;
      font-weight: 700;
      margin: 0;
    }
    .table-wrap {
      overflow-x: auto;
      max-height: 520px;
      overflow-y: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.84rem;
    }
    th, td {
      padding: 0.55rem 0.85rem;
      text-align: left;
      border-bottom: 1px solid rgba(37, 51, 77, 0.6);
    }
    th {
      position: sticky;
      top: 0;
      background: var(--panel-alt);
      color: var(--muted);
      font-weight: 600;
      font-size: 0.74rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
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
      text-align: right;
      font-family: var(--mono);
      white-space: nowrap;
    }
    .pill {
      display: inline-block;
      padding: 0.12rem 0.5rem;
      border-radius: 999px;
      font-size: 0.7rem;
      font-weight: 600;
      font-family: var(--mono);
    }
    .pill-strong, .pill-403 {
      background: rgba(244, 63, 94, 0.16);
      color: #fda4af;
      border: 1px solid rgba(244, 63, 94, 0.35);
    }
    .pill-weak, .pill-4xx {
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
    .pill-5xx {
      background: rgba(168, 85, 247, 0.2);
      color: #d8b4fe;
      border: 1px solid rgba(168, 85, 247, 0.45);
    }
    .status-strip {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      padding: 0.85rem 1.25rem;
      border-bottom: 1px solid var(--border);
      background: rgba(11, 15, 23, 0.45);
    }
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      padding: 0.3rem 0.65rem;
      border-radius: 6px;
      background: var(--panel-alt);
      border: 1px solid var(--border);
      font-family: var(--mono);
      font-size: 0.78rem;
      cursor: pointer;
    }
    .status-badge:hover {
      border-color: var(--accent);
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
        <h1>Cloudflare Edge Honeypot, Attack Origin & Traffic Dashboard</h1>
      </div>
      <div class="controls">
        <label for="days-select" style="color:var(--muted);font-size:0.82rem;">Window:</label>
        <select id="days-select">
          <option value="1">Last 24 Hours</option>
          <option value="7" selected>Last 7 Days</option>
          <option value="14">Last 14 Days</option>
        </select>
        <input type="search" id="path-filter" placeholder="Filter paths, domains, countries, or IPs..." style="min-width:250px;">
        <button class="primary" id="refresh-btn">Refresh Live Data</button>
      </div>
    </div>
  </header>

  <main>
    <section class="kpis">
      <div class="kpi">
        <div class="kpi-label">Total Edge Traffic (<span class="days-lbl">7d</span>)</div>
        <div class="kpi-val" id="kpi-all-requests">--</div>
        <div class="kpi-sub">All requests across 19 Cloudflare zones</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">2xx OK Responses</div>
        <div class="kpi-val" id="kpi-2xx" style="color:#6ee7b7;">--</div>
        <div class="kpi-sub" id="kpi-3xx-sub">3xx Redirects: --</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">403 Forbidden Blocks</div>
        <div class="kpi-val" id="kpi-403-blocks" style="color:#fda4af;">--</div>
        <div class="kpi-sub" id="kpi-404-sub">404 Not Found: -- | 5xx: --</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Honeypot Trap Hits (<span class="days-lbl">7d</span>)</div>
        <div class="kpi-val" id="kpi-trap-hits" style="color:#fcd34d;">--</div>
        <div class="kpi-sub"><span id="kpi-unique-paths">--</span> unique attack paths matched</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Active 24h KV Bans</div>
        <div class="kpi-val" id="kpi-active-bans" style="color:var(--accent);">--</div>
        <div class="kpi-sub" id="kpi-rules-count">-- configured rules</div>
      </div>
    </section>

    <!-- All Traffic Summary & Return Code Breakdown -->
    <section class="card">
      <div class="card-header">
        <div>
          <h2 class="card-title">All-Traffic & HTTP Return Code Summary (All 19 Cloudflare Zones)</h2>
          <div style="font-size:0.78rem;color:var(--muted);margin-top:0.15rem;">
            Live HTTP response status breakdown across all domains, plus searchable request log with return code, origin country, and honeypot classification. Click any status badge below to filter.
          </div>
        </div>
        <div style="display:flex;gap:0.5rem;align-items:center;">
          <select id="status-filter">
            <option value="all">All Status Codes</option>
            <option value="2xx">2xx Success (200, 204, 206)</option>
            <option value="3xx">3xx Redirect (301, 302, 304)</option>
            <option value="403">403 Forbidden Only</option>
            <option value="404">404 Not Found Only</option>
            <option value="4xx">All 4xx Client Errors</option>
            <option value="5xx">All 5xx Server Errors</option>
          </select>
          <select id="signal-filter">
            <option value="all">All Traffic (Clean + Traps)</option>
            <option value="clean">Clean Traffic Only</option>
            <option value="trap">Honeypot Traps Only</option>
          </select>
        </div>
      </div>

      <div class="status-strip" id="status-code-strip">
        <span style="color:var(--muted);font-size:0.8rem;">Loading HTTP status codes...</span>
      </div>

      <div class="grid-2" style="padding: 1rem 1.25rem; gap: 1.25rem;">
        <div>
          <div style="font-size:0.8rem;font-weight:700;color:var(--muted);margin-bottom:0.5rem;text-transform:uppercase;">
            Traffic & Return Code Matrix by Domain
          </div>
          <div class="table-wrap" style="max-height: 360px; border: 1px solid var(--border); border-radius: 8px;">
            <table>
              <thead>
                <tr>
                  <th>Domain Zone</th>
                  <th class="num">Total</th>
                  <th class="num" style="color:#6ee7b7;">2xx</th>
                  <th class="num" style="color:#7dd3fc;">3xx</th>
                  <th class="num" style="color:#fda4af;">403</th>
                  <th class="num" style="color:#fcd34d;">404</th>
                  <th class="num" style="color:#d8b4fe;">5xx</th>
                  <th class="num">Traps</th>
                </tr>
              </thead>
              <tbody id="domain-matrix-tbody">
                <tr><td colspan="8" style="color:var(--muted);">Loading domain traffic matrix...</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <div>
          <div style="font-size:0.8rem;font-weight:700;color:var(--muted);margin-bottom:0.5rem;text-transform:uppercase;">
            All Requests by Host, Path, Country & Return Code
          </div>
          <div class="table-wrap" style="max-height: 360px; border: 1px solid var(--border); border-radius: 8px;">
            <table>
              <thead>
                <tr>
                  <th class="num">Hits</th>
                  <th>Status</th>
                  <th>Signal</th>
                  <th>Country</th>
                  <th>Host</th>
                  <th>Method & Path</th>
                </tr>
              </thead>
              <tbody id="all-traffic-tbody">
                <tr><td colspan="6" style="color:var(--muted);">Loading all traffic log...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </section>

    <!-- Active KV Bans (with Geo/ASN/Host Attribution) & Attack Origin by Country -->
    <section class="grid-2">
      <div class="card">
        <div class="card-header">
          <div>
            <h2 class="card-title">Active 24-Hour Banned Source IPs in KV (Live Geo, ASN & Target Host)</h2>
            <div style="font-size:0.76rem;color:var(--muted);margin-top:0.1rem;">
              Every trap hit stores the attacker's IP, country, city, ASN/ISP organization, and target domain in <code>SECURITY_BANS</code> KV.
            </div>
          </div>
          <div style="display:flex;gap:0.4rem;">
            <input type="text" id="manual-ban-ip" placeholder="IP to ban..." style="width:140px;padding:0.3rem 0.5rem;">
            <button id="manual-ban-btn" class="danger">Ban IP</button>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Source IP</th>
                <th>Location</th>
                <th>Network / ASN</th>
                <th>Target Host</th>
                <th>Trigger Path</th>
                <th class="num">TTL</th>
                <th style="text-align:right;">Action</th>
              </tr>
            </thead>
            <tbody id="active-bans-tbody">
              <tr><td colspan="7" style="color:var(--muted);">Loading KV bans...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <div>
            <h2 class="card-title">Attack Origin by Country (All 19 Cloudflare Zones)</h2>
            <div style="font-size:0.76rem;color:var(--muted);margin-top:0.1rem;">
              Correlates where honeypot trap probes and 403 blocks are originating geographically across your domains.
            </div>
          </div>
        </div>
        <div class="table-wrap" style="max-height: 290px;">
          <table>
            <thead>
              <tr>
                <th>Country</th>
                <th class="num" style="color:#fcd34d;">Trap Hits</th>
                <th class="num" style="color:#fda4af;">403 Blocks</th>
                <th class="num">Total Requests</th>
                <th class="num">Trap %</th>
                <th class="num">Zones</th>
              </tr>
            </thead>
            <tbody id="country-origin-tbody">
              <tr><td colspan="6" style="color:var(--muted);">Loading country origin telemetry...</td></tr>
            </tbody>
          </table>
        </div>
        <div class="card-header" style="border-top:1px solid var(--border);">
          <h2 class="card-title">Active KV Bans Grouped by Trigger Path</h2>
        </div>
        <div class="table-wrap" style="max-height: 200px;">
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
                <th>Top Countries</th>
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
        <div class="table-wrap" style="max-height: 250px;">
          <table>
            <thead>
              <tr>
                <th style="text-align:right;">Hits</th>
                <th>Status</th>
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
        <div class="card-header" style="border-top:1px solid var(--border);">
          <h2 class="card-title">Honeypot Trap Hits by Domain Zone</h2>
        </div>
        <div id="zones-bars" style="padding: 0.6rem 0; max-height: 240px; overflow-y: auto;">
          <div style="padding:1rem 1.25rem;color:var(--muted);">Loading zone breakdown...</div>
        </div>
      </div>
    </section>
  </main>

  <script>
    let currentData = null;
    const regionNames = typeof Intl !== 'undefined' && Intl.DisplayNames
      ? new Intl.DisplayNames(['en'], { type: 'region' })
      : null;

    function formatCountry(code) {
      if (!code || code === 'XX' || code === 'T1') return code || '--';
      try {
        const name = regionNames ? regionNames.of(code.toUpperCase()) : code;
        return name ? \`\${code.toUpperCase()} (\${name})\` : code.toUpperCase();
      } catch {
        return code;
      }
    }

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
      if (code >= 200 && code < 300) return 'pill-2xx';
      if (code >= 300 && code < 400) return 'pill-3xx';
      if (code === 403) return 'pill-403';
      if (code >= 400 && code < 500) return 'pill-4xx';
      return 'pill-5xx';
    }

    function matchesStatusFilter(code, filterVal) {
      if (!filterVal || filterVal === 'all') return true;
      if (filterVal === '2xx') return code >= 200 && code < 300;
      if (filterVal === '3xx') return code >= 300 && code < 400;
      if (filterVal === '403') return code === 403;
      if (filterVal === '404') return code === 404;
      if (filterVal === '4xx') return code >= 400 && code < 500;
      if (filterVal === '5xx') return code >= 500;
      return Number(filterVal) === code;
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
      const statusFilter = document.getElementById('status-filter').value;
      const signalFilter = document.getElementById('signal-filter').value;
      const now = Date.now();

      const customCount =
        (currentData.customRules?.strongSegments?.length || 0) +
        (currentData.customRules?.weakSegments?.length || 0) +
        (currentData.customRules?.allowPaths?.length || 0);

      document.getElementById('kpi-active-bans').textContent = currentData.activeBans.length.toLocaleString();
      document.getElementById('kpi-rules-count').textContent =
        currentData.rulesCount.strongSegments + ' built-in + ' + customCount + ' KV overrides';

      const tel = currentData.telemetry;
      const st = tel.statusTotals || { s2xx: 0, s3xx: 0, s403: 0, s404: 0, s4xxOther: 0, s5xx: 0, byCode: [] };

      document.querySelectorAll('.days-lbl').forEach((el) => {
        el.textContent = tel.days + 'd';
      });
      document.getElementById('kpi-all-requests').textContent = (tel.totalAllRequests || 0).toLocaleString();
      document.getElementById('kpi-2xx').textContent = (st.s2xx || 0).toLocaleString();
      document.getElementById('kpi-3xx-sub').textContent = '3xx Redirects: ' + (st.s3xx || 0).toLocaleString();
      document.getElementById('kpi-403-blocks').textContent = (st.s403 || 0).toLocaleString();
      document.getElementById('kpi-404-sub').textContent =
        '404: ' + (st.s404 || 0).toLocaleString() + ' | 5xx: ' + (st.s5xx || 0).toLocaleString();
      document.getElementById('kpi-trap-hits').textContent = (tel.totalTrapHits || 0).toLocaleString();
      document.getElementById('kpi-unique-paths').textContent = (tel.uniqueTrapPaths || 0).toLocaleString();

      if (tel.error) {
        document.getElementById('telemetry-updated').textContent = tel.error;
      } else if (tel.generatedAt) {
        document.getElementById('telemetry-updated').textContent =
          'Updated ' + new Date(tel.generatedAt).toLocaleTimeString();
      }

      // Status code strip
      const stripEl = document.getElementById('status-code-strip');
      if ((st.byCode || []).length === 0) {
        stripEl.innerHTML = '<span style="color:var(--muted);font-size:0.8rem;">No status data.</span>';
      } else {
        stripEl.innerHTML = st.byCode
          .map(
            (item) => \`<div class="status-badge" data-status-code="\${item.status}" title="Click to filter by HTTP \${item.status}">
              <span class="pill \${statusPillClass(item.status)}">HTTP \${item.status}</span>
              <strong>\${item.count.toLocaleString()}</strong>
            </div>\`
          )
          .join('');
      }

      // Domain Matrix
      const domMatrix = (tel.domainMatrix || []).filter(
        (d) => !filter || d.zone.toLowerCase().includes(filter)
      );
      const domTbody = document.getElementById('domain-matrix-tbody');
      if (domMatrix.length === 0) {
        domTbody.innerHTML = '<tr><td colspan="8" style="color:var(--muted);">No matching domains.</td></tr>';
      } else {
        domTbody.innerHTML = domMatrix
          .map(
            (d) => \`<tr>
              <td class="mono" style="font-weight:600;">\${escapeHtml(d.zone)}</td>
              <td class="num" style="font-weight:700;">\${d.total.toLocaleString()}</td>
              <td class="num" style="color:#6ee7b7;">\${d.s2xx.toLocaleString()}</td>
              <td class="num" style="color:#7dd3fc;">\${d.s3xx.toLocaleString()}</td>
              <td class="num" style="color:#fda4af;font-weight:600;">\${d.s403.toLocaleString()}</td>
              <td class="num" style="color:#fcd34d;">\${d.s404.toLocaleString()}</td>
              <td class="num" style="color:#d8b4fe;">\${d.s5xx.toLocaleString()}</td>
              <td class="num">\${d.trapHits.toLocaleString()}</td>
            </tr>\`
          )
          .join('');
      }

      // All Traffic Rows
      const trafficRows = (tel.allTrafficRows || []).filter((r) => {
        if (
          filter &&
          !r.path.toLowerCase().includes(filter) &&
          !r.host.toLowerCase().includes(filter) &&
          !(r.topCountries || []).join(' ').toLowerCase().includes(filter)
        ) {
          return false;
        }
        if (!matchesStatusFilter(r.status, statusFilter)) return false;
        if (signalFilter === 'clean' && r.classification !== 'clean') return false;
        if (signalFilter === 'trap' && r.classification === 'clean') return false;
        return true;
      });

      const trafficTbody = document.getElementById('all-traffic-tbody');
      if (trafficRows.length === 0) {
        trafficTbody.innerHTML = '<tr><td colspan="6" style="color:var(--muted);">No matching requests for current filter.</td></tr>';
      } else {
        trafficTbody.innerHTML = trafficRows
          .slice(0, 200)
          .map((r) => {
            const sigClass =
              r.classification === 'strong'
                ? 'pill-strong'
                : r.classification === 'weak'
                ? 'pill-weak'
                : 'pill-clean';
            return \`<tr>
              <td class="num" style="font-weight:700;">\${r.count.toLocaleString()}x</td>
              <td><span class="pill \${statusPillClass(r.status)}">\${r.status}</span></td>
              <td><span class="pill \${sigClass}">\${escapeHtml(r.classification)}</span></td>
              <td class="mono" style="color:var(--muted);">\${escapeHtml((r.topCountries || []).join(', ') || '--')}</td>
              <td class="mono" style="color:var(--muted);">\${escapeHtml(r.host)}</td>
              <td class="mono"><strong style="color:var(--accent);">\${escapeHtml(r.method)}</strong> \${escapeHtml(r.path)}</td>
            </tr>\`;
          })
          .join('');
      }

      // 1. Active bans table (with Geo, ASN/Org, and Target Host)
      const filteredBans = currentData.activeBans.filter(
        (b) =>
          !filter ||
          b.ip.toLowerCase().includes(filter) ||
          b.path.toLowerCase().includes(filter) ||
          (b.country || '').toLowerCase().includes(filter) ||
          (b.city || '').toLowerCase().includes(filter) ||
          (b.asOrganization || '').toLowerCase().includes(filter) ||
          (b.host || '').toLowerCase().includes(filter)
      );
      const bansTbody = document.getElementById('active-bans-tbody');
      if (filteredBans.length === 0) {
        bansTbody.innerHTML = '<tr><td colspan="7" style="color:var(--muted);">No matching active bans.</td></tr>';
      } else {
        bansTbody.innerHTML = filteredBans
          .map((b) => {
            const locParts = [b.country, b.city, b.region].filter(Boolean);
            const locStr = locParts.length > 0 ? locParts.join(' / ') : 'Legacy ban (pre-geo)';
            const netStr = b.asOrganization
              ? \`\${b.asOrganization}\${b.asn ? ' (AS' + b.asn + ')' : ''}\`
              : b.asn
              ? 'AS' + b.asn
              : '--';
            return \`<tr>
              <td class="mono" style="font-weight:600;">\${escapeHtml(b.ip)}</td>
              <td class="mono">\${escapeHtml(locStr)}</td>
              <td class="mono" style="color:var(--muted);" title="\${escapeHtml(b.userAgent || '')}">\${escapeHtml(netStr)}</td>
              <td class="mono" style="color:var(--muted);">\${escapeHtml(b.host || '--')}</td>
              <td class="mono">\${escapeHtml(b.path)}</td>
              <td class="num">\${formatTtl((b.expiresAt || 0) - now)}</td>
              <td style="text-align:right;">
                <button class="danger" data-unban="\${escapeHtml(b.ip)}">Unban</button>
              </td>
            </tr>\`;
          })
          .join('');
      }

      // 1b. Attack Origin by Country table
      const filteredCountries = (tel.countries || []).filter(
        (c) =>
          !filter ||
          c.country.toLowerCase().includes(filter) ||
          formatCountry(c.country).toLowerCase().includes(filter)
      );
      const countryTbody = document.getElementById('country-origin-tbody');
      if (filteredCountries.length === 0) {
        countryTbody.innerHTML = '<tr><td colspan="6" style="color:var(--muted);">No matching country telemetry.</td></tr>';
      } else {
        countryTbody.innerHTML = filteredCountries
          .map((c) => {
            const pct = c.totalRequests > 0 ? Math.round((c.trapHits / c.totalRequests) * 100) : 0;
            return \`<tr>
              <td class="mono" style="font-weight:600;">\${escapeHtml(formatCountry(c.country))}</td>
              <td class="num" style="color:#fcd34d;font-weight:700;">\${c.trapHits.toLocaleString()}</td>
              <td class="num" style="color:#fda4af;">\${c.blocked403.toLocaleString()}</td>
              <td class="num">\${c.totalRequests.toLocaleString()}</td>
              <td class="num">\${pct}%</td>
              <td class="num">\${c.zoneCount}</td>
            </tr>\`;
          })
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
        (p) =>
          !filter ||
          p.path.toLowerCase().includes(filter) ||
          (p.topCountries || []).join(' ').toLowerCase().includes(filter)
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
              <td><span class="pill \${p.type === 'strong' ? 'pill-strong' : 'pill-weak'}">\${escapeHtml(p.type)}</span></td>
              <td class="mono" style="color:var(--muted);">\${escapeHtml((p.topCountries || []).join(', ') || '--')}</td>
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
              <td><span class="pill \${statusPillClass(p.status || 404)}">\${p.status || 404}</span></td>
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

      // 5. Zone bars
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
    document.getElementById('path-filter').addEventListener('input', renderAll);
    document.getElementById('status-filter').addEventListener('change', renderAll);
    document.getElementById('signal-filter').addEventListener('change', renderAll);
    document.getElementById('save-rules-btn').addEventListener('click', saveRulesNow);

    document.getElementById('status-code-strip').addEventListener('click', (e) => {
      const badge = e.target.closest('[data-status-code]');
      if (!badge) return;
      const code = badge.getAttribute('data-status-code');
      const select = document.getElementById('status-filter');
      let opt = [...select.options].find((o) => o.value === code);
      if (!opt) {
        opt = document.createElement('option');
        opt.value = code;
        opt.textContent = 'HTTP ' + code + ' Only';
        select.appendChild(opt);
      }
      select.value = select.value === code ? 'all' : code;
      renderAll();
    });

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
            host: 'cf-hp-stats.emerald-glen.com',
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
