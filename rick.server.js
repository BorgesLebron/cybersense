// agents/radar/rick.server.js
//
// Rick — Radar Data Engineer — SERVER AGENT.
// The first autonomous agent in the CyberSense Ops pipeline: runs on a
// schedule inside cybersense-ops (Railway), fetches CISA KEV + NVD,
// normalizes/dedupes into radar records, and pushes the result straight
// to api.cybersense.solutions' /api/content/radar (see radar-endpoint-sketch.js
// from the earlier conversation — that route needs to exist on the OTHER
// project before this will have anywhere to push to).
//
// KNOWN RISK: cybersense-ops' /api/fetch was already deprecated for Ruth
// because Cloudflare blocks Railway's outbound requests to at least one
// target site. Whether that block applies to cisa.gov / nist.gov specifically
// is untested. Don't trust the schedule blindly — trigger one manual run
// (POST /api/agents/rick/run) after deploying and read the response before
// assuming this works unattended. If CISA KEV fails outbound, this falls
// back to a community GitHub mirror automatically, but logs loudly when it
// does, since that mirror isn't an official CISA source.

import express from 'express';
import fs from 'fs/promises';
import path from 'path';

const router = express.Router();

const DATA_DIR = path.join(process.cwd(), 'data');
const CURRENT_ACTIVITY_PATH = path.join(DATA_DIR, 'rick-current-activity.json');
const LAST_RUN_PATH = path.join(DATA_DIR, 'rick-last-run.json');

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
// Community-maintained mirror, refreshed daily via GitHub Action. NOT an
// official CISA source — only used as a fallback, and every run that uses
// it is flagged in the status/warnings output.
const KEV_MIRROR_URL = 'https://raw.githubusercontent.com/BenjiTrapp/cisa-known-vuln-scraper/main/cisa-kev.json';
const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

/* ────────────────────────────────────────────────────────────────
   SHARED HELPERS (kept in lockstep with the browser Rick UI —
   same dedupe/severity rules, so a manual browser run and an
   autonomous server run never disagree on the same input data)
──────────────────────────────────────────────────────────────── */
function cvssToSeverity(score) {
  const n = parseFloat(score);
  if (Number.isNaN(n)) return null;
  if (n >= 9) return 'critical';
  if (n >= 7) return 'high';
  if (n >= 4) return 'medium';
  return 'low';
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function normalizeKEV(json) {
  const vulns = json.vulnerabilities || json.vulns || [];
  return vulns.map(v => {
    const ransomware = String(v.knownRansomwareCampaignUse || '').toLowerCase() === 'known';
    return {
      cve_id: (v.cveID || '').toUpperCase().trim(),
      threat_name: v.vulnerabilityName || `${v.vendorProject || ''} ${v.product || ''}`.trim(),
      vendor: v.vendorProject || '',
      product: v.product || '',
      description: v.shortDescription || '',
      date_added: v.dateAdded || '',
      due_date: v.dueDate || '',
      cvss_score: null,
      severity: ransomware ? 'critical' : 'high',
      threat_category: 'known_exploited_vulnerability',
      category: 'known_exploited_vulnerability',
      tags: [v.vendorProject, ransomware ? 'Ransomware' : null].filter(Boolean),
      source: ['cisa_kev']
    };
  }).filter(r => r.cve_id);
}

function nvdSeverityOf(cve) {
  const metrics = cve.metrics || {};
  const order = ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'];
  for (const key of order) {
    const arr = metrics[key];
    if (arr && arr.length) {
      const m = arr[0];
      const score = m.cvssData ? m.cvssData.baseScore : m.baseScore;
      const sev = m.baseSeverity || (m.cvssData && m.cvssData.baseSeverity) || cvssToSeverity(score) || 'low';
      return { score: score != null ? Number(score) : null, severity: String(sev).toLowerCase() };
    }
  }
  return { score: null, severity: 'low' };
}

function normalizeNVD(items) {
  return items.map(item => {
    const cve = item.cve || item;
    const id = (cve.id || cve.cveID || '').toUpperCase().trim();
    const descs = cve.descriptions || [];
    const enDesc = (descs.find(d => d.lang === 'en') || descs[0] || {}).value || '';
    const { score, severity } = nvdSeverityOf(cve);
    const weaknesses = (cve.weaknesses || []).flatMap(w =>
      (w.description || []).filter(d => d.lang === 'en').map(d => d.value)
    );
    return {
      cve_id: id,
      threat_name: enDesc.split(/(?<=[.!?])\s/)[0]?.slice(0, 140) || id,
      vendor: '',
      product: '',
      description: enDesc,
      date_added: (cve.published || '').slice(0, 10),
      due_date: '',
      cvss_score: score,
      severity: severity || cvssToSeverity(score) || 'low',
      threat_category: 'vulnerability',
      category: 'vulnerability',
      tags: weaknesses.slice(0, 3),
      source: ['nvd']
    };
  }).filter(r => r.cve_id);
}

function normalizeCA(rows) {
  const out = [];
  (rows || []).forEach(r => {
    const base = {
      threat_name: r.title,
      vendor: '', product: '',
      description: r.title,
      date_added: r.date,
      due_date: '',
      cvss_score: null,
      severity: r.severity || 'high',
      threat_category: 'us-cert-current-activity',
      category: 'us-cert-current-activity',
      article_link: r.url || '',
      tags: [],
      source: ['cisa_current_activity']
    };
    const cves = (r.cves || []).map(c => c.toUpperCase().trim()).filter(Boolean);
    if (cves.length) cves.forEach(cve => out.push({ ...base, cve_id: cve }));
    else out.push({ ...base, cve_id: '' });
  });
  return out;
}

function mergeAndDedupe(kevRecords, nvdRecords, caRecords) {
  const combined = [...kevRecords, ...nvdRecords, ...normalizeCA(caRecords)];
  const byCve = new Map();
  const noCveList = [];

  combined.forEach(rec => {
    if (!rec.cve_id) { noCveList.push({ ...rec }); return; }
    const key = rec.cve_id;
    if (!byCve.has(key)) { byCve.set(key, { ...rec, source: [...rec.source] }); return; }

    const existing = byCve.get(key);
    rec.source.forEach(s => { if (!existing.source.includes(s)) existing.source.push(s); });
    if (rec.threat_category === 'known_exploited_vulnerability') {
      existing.threat_category = 'known_exploited_vulnerability';
      existing.category = 'known_exploited_vulnerability';
    }
    if (rec.cvss_score != null && (existing.cvss_score == null || rec.cvss_score > existing.cvss_score)) {
      existing.cvss_score = rec.cvss_score;
    }
    if ((rec.description || '').length > (existing.description || '').length) existing.description = rec.description;
    if (!existing.vendor && rec.vendor) existing.vendor = rec.vendor;
    if (!existing.product && rec.product) existing.product = rec.product;
    (rec.tags || []).forEach(t => { if (t && !existing.tags.includes(t)) existing.tags.push(t); });
    if (rec.date_added && (!existing.date_added || rec.date_added < existing.date_added)) existing.date_added = rec.date_added;
    if (!existing.article_link && rec.article_link) existing.article_link = rec.article_link;
  });

  let merged = [...byCve.values(), ...noCveList];

  merged = merged.map(r => {
    let severity = r.severity;
    if (r.cvss_score != null) severity = cvssToSeverity(r.cvss_score) || severity;
    if (r.source.includes('cisa_kev') && !['critical', 'high'].includes(severity)) severity = 'high';
    return { ...r, severity };
  });

  merged.sort((a, b) => (b.date_added || '').localeCompare(a.date_added || ''));
  return merged;
}

function computeBreakdown(records) {
  return records.reduce((acc, r) => {
    const sev = r.severity || 'low';
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0 });
}

/* ────────────────────────────────────────────────────────────────
   FETCHERS
──────────────────────────────────────────────────────────────── */
async function fetchKEVServer() {
  try {
    const res = await fetch(KEV_URL, { signal: AbortSignal.timeout(20000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = await res.json();
    return { records: normalizeKEV(json), sourceUsed: 'cisa.gov (official)', warning: null };
  } catch (primaryErr) {
    console.warn('[Rick] Direct CISA KEV fetch failed, trying mirror:', primaryErr.message);
    try {
      const res = await fetch(KEV_MIRROR_URL, { signal: AbortSignal.timeout(20000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      return {
        records: normalizeKEV(json),
        sourceUsed: 'github mirror (unofficial fallback)',
        warning: `Direct CISA fetch failed (${primaryErr.message}) — used community mirror instead. Verify against cisa.gov before treating this run as authoritative.`
      };
    } catch (mirrorErr) {
      throw new Error(`CISA KEV unreachable both directly (${primaryErr.message}) and via mirror (${mirrorErr.message})`);
    }
  }
}

async function fetchNVDServer({ startDate, endDate, apiKey, maxRecords = 2000 }) {
  const resultsPerPage = 200;
  const delayMs = apiKey ? 700 : 6500;
  let startIndex = 0;
  let totalResults = Infinity;
  let all = [];

  while (startIndex < totalResults && all.length < maxRecords) {
    const params = new URLSearchParams({
      pubStartDate: `${startDate}T00:00:00.000`,
      pubEndDate: `${endDate}T23:59:59.999`,
      resultsPerPage: String(resultsPerPage),
      startIndex: String(startIndex)
    });
    const headers = apiKey ? { apiKey } : {};
    const res = await fetch(`${NVD_URL}?${params.toString()}`, { headers, signal: AbortSignal.timeout(25000) });
    if (!res.ok) throw new Error(`NVD HTTP ${res.status}`);
    const json = await res.json();
    totalResults = json.totalResults || 0;
    all = all.concat(json.vulnerabilities || []);
    startIndex += resultsPerPage;
    if (startIndex < totalResults && all.length < maxRecords) await sleep(delayMs);
  }
  return normalizeNVD(all);
}

async function pushToRadarAPI(payload) {
  const url = process.env.RADAR_PUSH_URL;
  const key = process.env.RADAR_ADMIN_KEY;
  if (!url || !key) {
    return { pushed: false, reason: 'RADAR_PUSH_URL or RADAR_ADMIN_KEY not configured — export computed but not pushed.' };
  }
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-admin-key': key },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(20000)
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Push to radar API failed: HTTP ${res.status} ${text.slice(0, 200)}`);
  }
  return { pushed: true };
}

/* ────────────────────────────────────────────────────────────────
   PERSISTED STATE
   NOTE: Railway's filesystem is ephemeral across redeploys unless a
   Volume is attached at DATA_DIR. Without a Volume, current-activity
   entries and last-run status reset on every deploy. Attach a Volume
   at /data (or wherever DATA_DIR resolves) once this is load-bearing.
──────────────────────────────────────────────────────────────── */
async function readJSONSafe(filePath, fallback) {
  try {
    return JSON.parse(await fs.readFile(filePath, 'utf-8'));
  } catch {
    return fallback;
  }
}

async function writeJSON(filePath, obj) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(obj, null, 2));
}

async function getCurrentActivity() {
  return readJSONSafe(CURRENT_ACTIVITY_PATH, []);
}

/* ────────────────────────────────────────────────────────────────
   PIPELINE ORCHESTRATION
──────────────────────────────────────────────────────────────── */
let isRunning = false;

async function runRickPipeline({ triggeredBy = 'schedule' } = {}) {
  if (isRunning) {
    return { ok: false, error: 'A run is already in progress.' };
  }
  isRunning = true;
  const startedAt = new Date().toISOString();
  const warnings = [];
  const errors = [];
  let kevRecords = [];
  let nvdRecords = [];

  try {
    try {
      const kevResult = await fetchKEVServer();
      kevRecords = kevResult.records;
      if (kevResult.warning) warnings.push(kevResult.warning);
      console.log(`[Rick] KEV: ${kevRecords.length} records via ${kevResult.sourceUsed}`);
    } catch (e) {
      errors.push(`KEV fetch failed: ${e.message}`);
      console.error('[Rick] KEV fetch failed entirely:', e.message);
    }

    try {
      const end = new Date();
      const start = new Date(); start.setDate(start.getDate() - 7);
      nvdRecords = await fetchNVDServer({
        startDate: start.toISOString().slice(0, 10),
        endDate: end.toISOString().slice(0, 10),
        apiKey: process.env.NVD_API_KEY || null
      });
      console.log(`[Rick] NVD: ${nvdRecords.length} records`);
    } catch (e) {
      errors.push(`NVD fetch failed: ${e.message}`);
      console.error('[Rick] NVD fetch failed entirely:', e.message);
    }

    const caRecords = await getCurrentActivity();
    const merged = mergeAndDedupe(kevRecords, nvdRecords, caRecords);

    const exportPayload = {
      data: merged,
      meta: {
        total: merged.length,
        breakdown: computeBreakdown(merged),
        generated: new Date().toISOString(),
        generated_by: `Rick (server agent, triggered by ${triggeredBy})`,
        sources: { cisa_kev: kevRecords.length, nvd: nvdRecords.length, cisa_current_activity: caRecords.length }
      }
    };

    let pushResult = { pushed: false, reason: 'skipped — no records to push' };
    if (merged.length) {
      try {
        pushResult = await pushToRadarAPI(exportPayload);
      } catch (e) {
        errors.push(`Push failed: ${e.message}`);
        console.error('[Rick] Push to radar API failed:', e.message);
      }
    }

    const summary = {
      ok: errors.length === 0,
      startedAt,
      finishedAt: new Date().toISOString(),
      triggeredBy,
      counts: exportPayload.meta.sources,
      merged: merged.length,
      breakdown: exportPayload.meta.breakdown,
      pushResult,
      warnings,
      errors
    };

    await writeJSON(LAST_RUN_PATH, summary);
    return summary;
  } finally {
    isRunning = false;
  }
}

/* ────────────────────────────────────────────────────────────────
   SCHEDULER — simple in-process interval. Runs as long as the
   Railway web service is up; no separate cron service required.
   Set RICK_INTERVAL_HOURS=0 to disable and trigger runs externally
   instead (e.g. a Railway Cron Job service hitting /api/agents/rick/run).
──────────────────────────────────────────────────────────────── */
export function scheduleRick() {
  const hours = Number(process.env.RICK_INTERVAL_HOURS ?? 12);
  if (!hours || hours <= 0) {
    console.log('[Rick] Scheduler disabled (RICK_INTERVAL_HOURS=0). Trigger runs via POST /api/agents/rick/run.');
    return;
  }
  console.log(`[Rick] Scheduler active — running every ${hours}h.`);
  setInterval(() => {
    runRickPipeline({ triggeredBy: 'schedule' }).catch(e => console.error('[Rick] Scheduled run threw:', e));
  }, hours * 60 * 60 * 1000);
}

/* ────────────────────────────────────────────────────────────────
   ROUTES
──────────────────────────────────────────────────────────────── */
function requireAgentKey(req, res, next) {
  const key = req.get('x-agent-key');
  if (!process.env.RICK_AGENT_KEY || key !== process.env.RICK_AGENT_KEY) {
    return res.status(401).json({ error: { message: 'Unauthorized.' } });
  }
  next();
}

router.post('/api/agents/rick/run', requireAgentKey, async (req, res) => {
  try {
    const summary = await runRickPipeline({ triggeredBy: 'manual' });
    return res.status(summary.ok === false && summary.error ? 409 : 200).json(summary);
  } catch (e) {
    console.error('[Rick] Manual run failed:', e);
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// Read-only, unauthenticated — just status, no sensitive data.
router.get('/api/agents/rick/status', async (req, res) => {
  const last = await readJSONSafe(LAST_RUN_PATH, null);
  return res.json({ lastRun: last, schedulerIntervalHours: Number(process.env.RICK_INTERVAL_HOURS ?? 12) });
});

router.get('/api/agents/rick/current-activity', async (req, res) => {
  return res.json({ data: await getCurrentActivity() });
});

router.post('/api/agents/rick/current-activity', requireAgentKey, express.json(), async (req, res) => {
  const { title, cves, date, severity, url } = req.body || {};
  if (!title) return res.status(400).json({ error: { message: 'title is required.' } });
  const rows = await getCurrentActivity();
  rows.push({
    title,
    cves: Array.isArray(cves) ? cves : String(cves || '').split(',').map(s => s.trim()).filter(Boolean),
    date: date || new Date().toISOString().slice(0, 10),
    severity: severity || 'high',
    url: url || ''
  });
  await writeJSON(CURRENT_ACTIVITY_PATH, rows);
  return res.json({ ok: true, count: rows.length });
});

router.delete('/api/agents/rick/current-activity/:index', requireAgentKey, async (req, res) => {
  const idx = parseInt(req.params.index, 10);
  const rows = await getCurrentActivity();
  if (idx < 0 || idx >= rows.length) return res.status(404).json({ error: { message: 'Index out of range.' } });
  rows.splice(idx, 1);
  await writeJSON(CURRENT_ACTIVITY_PATH, rows);
  return res.json({ ok: true, count: rows.length });
});

export default router;
export { runRickPipeline, mergeAndDedupe, normalizeKEV, normalizeNVD };
