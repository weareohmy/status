import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const DATOCMS_URL =
  "https://status.datocms.com/api/component-status?days=60";

const NETLIFY_URL =
  "https://www.netlifystatus.com/api/v2/summary.json";

async function fetchJson(url, timeoutMs = 15000) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "user-agent": "StatusMonitor/1.0" }
    });
    clearTimeout(t);

    if (!res.ok) {
      return { ok: false, httpStatus: res.status, error: `HTTP ${res.status}`, json: null };
    }

    const json = await res.json();
    return { ok: true, httpStatus: res.status, error: null, json };
  } catch (e) {
    clearTimeout(t);
    return { ok: false, httpStatus: null, error: String(e), json: null };
  }
}

// ---------- Dato parsing ----------

function normalizeDatoStatus(status) {
  const v = String(status ?? "").toLowerCase();
  if (v === "up") return "operational";
  if (v === "down") return "outage";
  if (v === "degraded") return "degraded";
  return v || "unknown";
}

function datoIdToName(id) {
  const mapping = {
    "cda": "Content Delivery API",
    "cma": "Content Management API",
    "assets": "Assets CDN",
    "administrativeAreas": "Projects administrative interface",
    "dashboard": "Account dashboard interface",
    "site": "Website",
  };
  return mapping[String(id)] || id;
}

function datoSummary(components) {
  const states = components.map((c) => c.status);
  if (states.includes("outage")) return "outage";
  if (states.includes("degraded")) return "degraded";
  if (states.includes("maintenance")) return "maintenance";
  if (states.includes("operational")) return "operational";
  return "unknown";
}

function parseDato(json) {
  if (!Array.isArray(json)) {
    return { ok: false, error: "Unexpected payload (expected array)", summary: "unknown", components: [] };
  }

  const components = json.map((c) => ({
    id: String(c.id ?? "unknown"),
    name: datoIdToName(c.id),
    status: normalizeDatoStatus(c.status),
  }));

  return { ok: true, error: null, summary: datoSummary(components), components };
}

// ---------- Netlify (Statuspage) parsing ----------

function normalizeStatuspageStatus(status) {
  // Statuspage statuses are typically:
  // operational, degraded_performance, partial_outage, major_outage, under_maintenance
  const v = String(status ?? "").toLowerCase();
  if (!v) return "unknown";
  if (v === "operational") return "operational";
  if (v === "degraded_performance") return "degraded";
  if (v === "partial_outage") return "degraded";
  if (v === "major_outage") return "outage";
  if (v === "under_maintenance") return "maintenance";
  return v;
}

function netlifySummaryFromStatuspageIndicator(indicator) {
  const v = String(indicator ?? "").toLowerCase();
  // indicator values often: none, minor, major, critical, maintenance
  if (v === "none") return "operational";
  if (v === "minor") return "degraded";
  if (v === "major" || v === "critical") return "outage";
  if (v === "maintenance") return "maintenance";
  return "unknown";
}

function parseNetlify(json) {
  const page = json?.page;
  const status = json?.status;
  const componentsRaw = Array.isArray(json?.components) ? json.components : [];

  const components = componentsRaw
    .filter((c) => c && c.group !== true && c.group_id === null) // drop group headers; keep real components
    .map((c) => ({
      id: String(c.id ?? "unknown"),
      name: String(c.name ?? "unknown"),
      status: normalizeStatuspageStatus(c.status),
    }));

  return {
    ok: Boolean(page?.id),
    error: page?.id ? null : "Unexpected payload (missing page)",
    summary: netlifySummaryFromStatuspageIndicator(status?.indicator),
    page: page
      ? { id: page.id, name: page.name, url: page.url, updatedAt: page.updated_at, timeZone: page.time_zone }
      : null,
    components
  };
}

// ---------- main ----------

async function main() {
  const generatedAt = new Date().toISOString();

  const [datoRes, netlifyRes] = await Promise.all([
    fetchJson(DATOCMS_URL),
    fetchJson(NETLIFY_URL)
  ]);

  const services = {
    generatedAt,
    providers: {
      datocms: {
        source: DATOCMS_URL,
        fetchedAt: generatedAt,
        ok: datoRes.ok,
        httpStatus: datoRes.httpStatus,
        error: datoRes.error,
        summary: "unknown",
        components: []
      },
      netlify: {
        source: NETLIFY_URL,
        fetchedAt: generatedAt,
        ok: netlifyRes.ok,
        httpStatus: netlifyRes.httpStatus,
        error: netlifyRes.error,
        summary: "unknown",
        page: null,
        components: []
      }
    }
  };

  if (datoRes.ok) {
    const parsed = parseDato(datoRes.json);
    services.providers.datocms.ok = parsed.ok;
    services.providers.datocms.error = parsed.error;
    services.providers.datocms.summary = parsed.summary;
    services.providers.datocms.components = parsed.components;
  }

  if (netlifyRes.ok) {
    const parsed = parseNetlify(netlifyRes.json);
    services.providers.netlify.ok = parsed.ok;
    services.providers.netlify.error = parsed.error;
    services.providers.netlify.summary = parsed.summary;
    services.providers.netlify.components = parsed.components;
  }

  const publicDir = path.join(__dirname, "../public");
  await fs.mkdir(publicDir, { recursive: true });

  const filePath = path.join(publicDir, "services.json");
  await fs.writeFile(filePath, JSON.stringify(services, null, 2), "utf-8");

  console.log(`Wrote ${filePath}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
