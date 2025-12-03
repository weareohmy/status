import fs from "node:fs/promises";
import tls from "node:tls";
import sites from "../config/sites.json" assert { type: "json" };

async function checkHttp(url, timeoutMs = 10000) {
  const start = Date.now();
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: { "user-agent": "StatusMonitor/1.0" }
    });
    clearTimeout(t);
    return { ok: res.status >= 200 && res.status < 400, status: res.status, ms: Date.now() - start, error: null };
  } catch (e) {
    clearTimeout(t);
    return { ok: false, status: null, ms: null, error: String(e) };
  }
}

async function checkCert(hostname, port = 443) {
  return await new Promise((resolve) => {
    const socket = tls.connect(
      { host: hostname, port, servername: hostname, timeout: 10000 },
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
}

async function checkDomainRdap(domain) {
  try {
    const boot = await fetch("https://data.iana.org/rdap/dns.json").then((r) => r.json());
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

async function main() {
  const out = { generatedAt: new Date().toISOString(), sites: {} };

  for (const s of sites) {
    const http = await checkHttp(s.url);
    const ssl = await checkCert(s.host);
    const domain = s.domain ? await checkDomainRdap(s.domain) : null;

    out.sites[s.slug] = {
      meta: { name: s.name, url: s.url },
      http,
      ssl,
      domain
    };
  }

  await fs.mkdir("public", { recursive: true });
  await fs.writeFile("public/status.json", JSON.stringify(out, null, 2));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
