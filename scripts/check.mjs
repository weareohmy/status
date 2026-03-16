import fs from "node:fs/promises";
import dns from "node:dns/promises";
import tls from "node:tls";
import sites from "../config/sites.json" with { type: 'json' };

/* ── HTTP check ─────────────────────────────────────────────── */

async function checkHttp(url, timeoutMs = 15000, retries = 2) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const start = Date.now();
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(url, {
        method: "HEAD",
        redirect: "follow",
        signal: controller.signal,
        headers: { "user-agent": "StatusMonitor/1.0" }
      });
      clearTimeout(t);
      return { ok: res.status >= 200 && res.status < 400, status: res.status, ms: Date.now() - start, error: null };
    } catch (e) {
      clearTimeout(t);
      if (attempt < retries) {
        await new Promise(r => setTimeout(r, 2000));
        continue;
      }
      return { ok: false, status: null, ms: null, error: String(e) };
    }
  }
}

/* ── SSL certificate check ──────────────────────────────────── */

async function checkCert(hostname, port = 443, retries = 2) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const result = await new Promise((resolve) => {
      const socket = tls.connect(
        { host: hostname, port, servername: hostname, timeout: 15000 },
        () => {
          const cert = socket.getPeerCertificate();
          socket.end();

          const notAfter = cert?.valid_to ? new Date(cert.valid_to) : null;
          const daysLeft = notAfter ? Math.ceil((notAfter - new Date()) / 86400000) : null;

          resolve({
            ok: Boolean(notAfter),
            expiresAt: notAfter?.toISOString() ?? null,
            daysLeft,
            issuer: cert?.issuer?.O ?? null,
            subject: cert?.subject?.CN ?? null
          });
        }
      );

      socket.on("error", (e) => resolve({ ok: false, expiresAt: null, daysLeft: null, error: String(e) }));
      socket.on("timeout", () => {
        socket.destroy();
        resolve({ ok: false, expiresAt: null, daysLeft: null, error: "timeout" });
      });
    });

    if (result.ok || attempt >= retries) return result;
    await new Promise(r => setTimeout(r, 2000));
  }
}

/* ── Domain expiry via RDAP ─────────────────────────────────── */

let rdapBootstrap = null;

async function getRdapBootstrap() {
  if (rdapBootstrap) return rdapBootstrap;
  rdapBootstrap = await fetch("https://data.iana.org/rdap/dns.json").then((r) => r.json());
  return rdapBootstrap;
}

async function checkDomainRdap(domain) {
  try {
    const boot = await getRdapBootstrap();
    const tld = domain.split(".").pop().toLowerCase();
    const service = boot.services.find(([tlds]) => tlds.map((x) => x.toLowerCase()).includes(tld));
    if (!service) return { ok: false, expiresAt: null, daysLeft: null, error: "No RDAP service for TLD" };

    const rdapBase = service[1][0];
    const data = await fetch(`${rdapBase}domain/${domain}`).then((r) => r.json());

    const expEvent = (data.events || []).find((e) =>
      ["expiration", "expiry", "expires"].includes(String(e.eventAction).toLowerCase())
    );

    const expiresAt = expEvent?.eventDate ? new Date(expEvent.eventDate) : null;
    if (!expiresAt) return { ok: false, expiresAt: null, daysLeft: null, error: "Expiration not provided via RDAP" };

    const daysLeft = Math.ceil((expiresAt - new Date()) / 86400000);
    return { ok: true, expiresAt: expiresAt.toISOString(), daysLeft, source: rdapBase };
  } catch (e) {
    return { ok: false, expiresAt: null, daysLeft: null, error: String(e) };
  }
}

/* ── DNS resolution check ───────────────────────────────────── */

const NETLIFY_LB = "75.2.60.5";

async function checkDns(hostname, timeoutMs = 15000) {
  try {
    const result = await Promise.race([
      (async () => {
        let cname = null;
        try { cname = (await dns.resolveCname(hostname))[0] ?? null; } catch {}
        const ipv4 = await dns.resolve4(hostname);

        /* Also resolve root/apex A record when host is www */
        let rootA = null;
        if (hostname.startsWith("www.")) {
          const apex = hostname.slice(4);
          try { rootA = await dns.resolve4(apex); } catch {}
        }

        /* Validate Netlify configuration */
        const cnameValid = cname ? /\.netlify\.(app|com)$/.test(cname) : false;
        const rootValid = rootA ? rootA.includes(NETLIFY_LB) : null;

        return { cname, a: ipv4, rootA, cnameValid, rootValid };
      })(),
      new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), timeoutMs))
    ]);
    return {
      ok: true,
      cname: result.cname, a: result.a, rootA: result.rootA,
      cnameValid: result.cnameValid, rootValid: result.rootValid,
      error: null
    };
  } catch (e) {
    return { ok: false, cname: null, a: [], rootA: null, cnameValid: false, rootValid: null, error: String(e) };
  }
}

/* ── Per-site orchestration ─────────────────────────────────── */

async function checkSite(s) {
  const [http, ssl, domain, dnsResult] = await Promise.all([
    checkHttp(s.url),
    checkCert(s.host),
    s.domain ? checkDomainRdap(s.domain) : Promise.resolve(null),
    checkDns(s.host)
  ]);
  return [s.slug, { meta: { name: s.name, url: s.url }, http, ssl, domain, dns: dnsResult }];
}

/* ── Main ───────────────────────────────────────────────────── */

async function main() {
  const out = { generatedAt: new Date().toISOString(), sites: {} };

  /* Pre-fetch the RDAP bootstrap file once before checking sites */
  await getRdapBootstrap().catch(() => {});

  /* Check sites in batches of 3 to avoid overwhelming the runner */
  const results = [];
  for (let i = 0; i < sites.length; i += 3) {
    const batch = sites.slice(i, i + 3);
    const batchResults = await Promise.all(batch.map(checkSite));
    results.push(...batchResults);
  }

  for (const [slug, data] of results) {
    out.sites[slug] = data;
  }

  await fs.mkdir("public", { recursive: true });
  await fs.writeFile("public/status.json", JSON.stringify(out, null, 2));

  /* Uptime history — 7-day rolling window */
  let history;
  try {
    history = JSON.parse(await fs.readFile("public/history.json", "utf-8"));
  } catch {
    history = { sites: {} };
  }

  const now = new Date().toISOString();
  for (const [slug, data] of results) {
    if (!history.sites[slug]) history.sites[slug] = [];
    history.sites[slug].push({ t: now, ok: data.http.ok });
  }

  const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
  for (const slug of Object.keys(history.sites)) {
    history.sites[slug] = history.sites[slug].filter(
      (e) => new Date(e.t).getTime() >= cutoff
    );
  }

  await fs.writeFile("public/history.json", JSON.stringify(history));
  console.log(`Checked ${results.length} site(s)`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
