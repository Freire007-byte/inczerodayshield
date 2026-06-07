import express from "express";
import cors from "cors";
import https from "https";
import http from "http";
import net from "net";
import dns from "dns";
import tls from "tls";
import { URL } from "url";
import { createRequire } from "module";
const require = createRequire(import.meta.url);
try { require("dotenv").config(); } catch {}

const app = express();
app.use(cors());
app.use(express.json());

// ─── TCP port probe ──────────────────────────────────────────────────────────
function probePort(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    sock.setTimeout(timeout);
    sock.connect(port, host, () => {
      sock.destroy();
      resolve({ port, open: true });
    });
    sock.on("error", () => resolve({ port, open: false }));
    sock.on("timeout", () => { sock.destroy(); resolve({ port, open: false, timeout: true }); });
  });
}

async function scanPorts(host) {
  const PORTS = [
    { port: 21,    svc: "FTP" },
    { port: 22,    svc: "SSH" },
    { port: 23,    svc: "Telnet" },
    { port: 25,    svc: "SMTP" },
    { port: 80,    svc: "HTTP" },
    { port: 443,   svc: "HTTPS" },
    { port: 445,   svc: "SMB" },
    { port: 3000,  svc: "Node/Grafana" },
    { port: 3306,  svc: "MySQL" },
    { port: 3389,  svc: "RDP" },
    { port: 4000,  svc: "Node/Dev" },
    { port: 5000,  svc: "Flask/Dev" },
    { port: 5432,  svc: "PostgreSQL" },
    { port: 5601,  svc: "Kibana" },
    { port: 6379,  svc: "Redis" },
    { port: 8080,  svc: "HTTP-Alt/Jenkins" },
    { port: 8443,  svc: "HTTPS-Alt" },
    { port: 8888,  svc: "Jupyter" },
    { port: 9090,  svc: "Prometheus" },
    { port: 9200,  svc: "Elasticsearch" },
    { port: 27017, svc: "MongoDB" },
    { port: 2375,  svc: "Docker API" },
    { port: 2376,  svc: "Docker TLS" },
    { port: 6443,  svc: "Kubernetes API" },
    { port: 11211, svc: "Memcached" },
  ];
  const results = await Promise.all(PORTS.map(({ port, svc }) =>
    probePort(host, port).then(r => ({ ...r, svc }))
  ));
  return results;
}

// ─── HTTP helpers ────────────────────────────────────────────────────────────
function fetchReq(rawUrl, method = "GET", extraHeaders = {}, timeout = 10000) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (val) => { if (!done) { done = true; resolve(val); } };
    // Hard deadline — guarantees resolve even if socket hangs mid-response
    const hardTimer = setTimeout(() => finish({ ok: false, timeout: true }), timeout);
    try {
      const u = new URL(rawUrl);
      const mod = u.protocol === "https:" ? https : http;
      let body = "";
      const req = mod.request({
        hostname: u.hostname,
        port: u.port || (u.protocol === "https:" ? 443 : 80),
        path: u.pathname + u.search,
        method,
        timeout,
        headers: { "User-Agent": "Mozilla/5.0 INC-SecurityScanner/2.0", ...extraHeaders },
      }, (res) => {
        res.setEncoding("utf8");
        res.on("data", (d) => { body += d; if (body.length > 80000) req.destroy(); });
        res.on("end", () => { clearTimeout(hardTimer); finish({ status: res.statusCode, headers: res.headers, body, ok: true }); });
      });
      req.on("error", () => { clearTimeout(hardTimer); finish({ ok: false, timeout: true }); });
      req.on("timeout", () => { req.destroy(); });
      req.end();
    } catch (e) { clearTimeout(hardTimer); finish({ ok: false, err: e.message }); }
  });
}

// ─── Rate limit test ─────────────────────────────────────────────────────────
async function testRateLimit(baseUrl, path = "/", count = 20) {
  const url = baseUrl.replace(/\/$/, "") + path;
  const reqs = Array.from({ length: count }, () => fetchReq(url, "GET", {}, 5000));
  const results = await Promise.all(reqs);
  const statuses = results.map(r => r.status).filter(Boolean);
  const has429 = statuses.includes(429);
  const has503 = statuses.includes(503);
  return {
    sent: count,
    statuses,
    has429,
    has503,
    rateLimited: has429 || has503,
    unique: [...new Set(statuses)],
  };
}

// ─── SSL/TLS deep check ──────────────────────────────────────────────────────
function checkSSL(hostname, port = 443) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: hostname, port,
      rejectUnauthorized: false,
      timeout: 8000,
    }, () => {
      const cert = socket.getPeerCertificate(true);
      const proto = socket.getProtocol();
      const cipher = socket.getCipher();
      socket.end();
      if (!cert || !cert.valid_to) return resolve({ ok: false });
      const expiry = new Date(cert.valid_to);
      const daysLeft = Math.floor((expiry - Date.now()) / 86400000);
      const weakCiphers = ["RC4", "DES", "3DES", "EXPORT", "NULL", "MD5"];
      const cipherName = cipher?.name || "";
      const isWeakCipher = weakCiphers.some(w => cipherName.toUpperCase().includes(w));
      const weakProtos = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"];
      const isWeakProto = weakProtos.some(p => proto === p);
      resolve({
        ok: true,
        subject: cert.subject?.CN || "",
        issuer: cert.issuer?.O || "",
        expiry: cert.valid_to,
        daysLeft,
        protocol: proto,
        cipher: cipherName,
        isWeakCipher,
        isWeakProto,
        selfSigned: cert.issuer?.CN === cert.subject?.CN,
        san: cert.subjectaltname || "",
      });
    });
    socket.on("error", (e) => resolve({ ok: false, err: e.message }));
    socket.on("timeout", () => { socket.destroy(); resolve({ ok: false, timeout: true }); });
  });
}

// ─── DNS deep check ──────────────────────────────────────────────────────────
async function checkDNS(hostname) {
  const safe = (fn) => Promise.race([fn.catch(() => []), new Promise(r => setTimeout(() => r([]), 5000))]);
  const dmarcHost = `_dmarc.${hostname}`;
  const [mx, txt, a, aaaa, ns, dmarcTxt] = await Promise.all([
    safe(dns.promises.resolveMx(hostname)),
    safe(dns.promises.resolveTxt(hostname)),
    safe(dns.promises.resolve4(hostname)),
    safe(dns.promises.resolve6(hostname)),
    safe(dns.promises.resolveNs(hostname)),
    safe(dns.promises.resolveTxt(dmarcHost)),
  ]);
  const txtFlat = txt.flat().map(t => Array.isArray(t) ? t.join("") : t);
  const dmarcFlat = dmarcTxt.flat().map(t => Array.isArray(t) ? t.join("") : t);
  return {
    mx: mx.map(r => r.exchange),
    txt: txtFlat,
    a,
    aaaa,
    ns,
    hasSPF:   txtFlat.some(t => t.startsWith("v=spf1")),
    hasDKIM:  txtFlat.some(t => t.includes("v=DKIM1")),
    hasDMARC: dmarcFlat.some(t => t.startsWith("v=DMARC1")),
    dmarcRecord: dmarcFlat[0] || null,
    spfRecord: txtFlat.find(t => t.startsWith("v=spf1")) || null,
  };
}

// ─── Exposed paths check ─────────────────────────────────────────────────────
async function checkPaths(base) {
  const paths = [
    // credenciais
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/.env.backup", "/.env.old", "/.env.bak",
    // git / vcs
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    "/.svn/entries", "/.hg/hgrc",
    // config files
    "/config.json", "/config.js", "/config.php", "/database.yml",
    "/settings.py", "/settings.json", "/wp-config.php",
    "/application.properties", "/appsettings.json",
    // admin panels
    "/admin", "/admin/", "/admin/login", "/wp-admin",
    "/phpmyadmin", "/pma", "/panel", "/dashboard",
    "/manager", "/console", "/control",
    // backups
    "/backup.zip", "/backup.sql", "/dump.sql", "/db.sql",
    "/backup.tar.gz", "/site.zip", "/www.zip",
    // info leakage
    "/phpinfo.php", "/info.php", "/server-status",
    "/server-info", "/.htaccess", "/web.config",
    // logs
    "/logs/", "/error.log", "/access.log", "/debug.log",
    "/app.log", "/laravel.log", "/storage/logs/laravel.log",
    // api / docs
    "/api", "/api/v1", "/api/v2", "/graphql",
    "/swagger.json", "/swagger-ui.html", "/openapi.json",
    "/api-docs", "/redoc",
    // monitoring
    "/metrics", "/health", "/status", "/actuator",
    "/actuator/env", "/actuator/heapdump",
    // other
    "/robots.txt", "/sitemap.xml", "/.DS_Store",
    "/package.json", "/composer.json", "/requirements.txt",
    "/Dockerfile", "/docker-compose.yml",
  ];
  const results = {};
  await Promise.all(paths.map(async (p) => {
    const r = await fetchReq(base + p, "HEAD", {}, 4000);
    results[p] = r.ok ? r.status : null;
  }));
  return results;
}

// ─── Slowloris test (lightweight — just tests timeout behavior) ───────────────
async function testSlowloris(hostname, port = 443) {
  return new Promise((resolve) => {
    try {
      const sock = new net.Socket();
      sock.connect(port, hostname, () => {
        // send partial HTTP headers, wait 5s to see if connection stays open
        sock.write(`GET / HTTP/1.1\r\nHost: ${hostname}\r\nX-Test: `);
        const timer = setTimeout(() => {
          sock.destroy();
          resolve({ vulnerable: true, detail: "Conexão parcial mantida aberta por 5s — potencialmente vulnerável a Slowloris" });
        }, 5000);
        sock.on("close", () => { clearTimeout(timer); resolve({ vulnerable: false, detail: "Servidor fechou a conexão parcial" }); });
        sock.on("error", () => { clearTimeout(timer); resolve({ vulnerable: false, detail: "Conexão recusada" }); });
      });
      sock.on("error", () => resolve({ vulnerable: false, detail: "Não foi possível conectar" }));
      sock.setTimeout(8000, () => { sock.destroy(); resolve({ vulnerable: false }); });
    } catch { resolve({ vulnerable: false }); }
  });
}

// ─── HTTP methods check ──────────────────────────────────────────────────────
async function checkMethods(url) {
  const methods = ["OPTIONS", "PUT", "DELETE", "TRACE", "PATCH"];
  const results = {};
  await Promise.all(methods.map(async (m) => {
    const r = await fetchReq(url, m, {}, 4000);
    results[m] = r.ok ? r.status : null;
  }));
  // parse Allow header from OPTIONS
  const opt = await fetchReq(url, "OPTIONS", {}, 4000);
  results.allowHeader = opt.headers?.allow || null;
  return results;
}

// ─── JS secrets scanner ──────────────────────────────────────────────────────
const SECRET_PATTERNS = [
  { name: "AWS Access Key",     rx: /AKIA[0-9A-Z]{16}/g },
  { name: "Google API Key",     rx: /AIza[0-9A-Za-z_\-]{35}/g },
  { name: "GitHub Token",       rx: /ghp_[A-Za-z0-9]{36}/g },
  { name: "Stripe Live Key",    rx: /sk_live_[A-Za-z0-9]{24,}/g },
  { name: "JWT Token",          rx: /eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/g },
  { name: "Private Key PEM",    rx: /-----BEGIN [A-Z ]* PRIVATE KEY-----/g },
  { name: "Database URL",       rx: /(mongodb|mysql|postgres|redis):\/\/[a-zA-Z0-9:@._\-\/]+/g },
  { name: "API Key hardcoded",  rx: /["'](api[_-]?key|apikey|api_secret)["']\s*[:=]\s*["']([a-zA-Z0-9_\-]{16,})["']/gi },
  { name: "Password hardcoded", rx: /["'](password|passwd|pwd)["']\s*[:=]\s*["']([^"']{8,})["']/gi },
  { name: "Token hardcoded",    rx: /["'](token|access_token|auth_token|secret_key)["']\s*[:=]\s*["']([a-zA-Z0-9_\-\.]{20,})["']/gi },
  { name: "Anthropic API Key",  rx: /sk-ant-[A-Za-z0-9_\-]{40,}/g },
  { name: "OpenAI API Key",     rx: /sk-[A-Za-z0-9T]{48}/g },
];

function runSecretScan(text, source) {
  const found = [];
  for (const p of SECRET_PATTERNS) {
    const rx = new RegExp(p.rx.source, p.rx.flags);
    const m = rx.exec(text);
    if (m) found.push({ source, type: p.name, sample: m[0].slice(0, 100) });
  }
  return found;
}

async function scanJsSecrets(htmlBody, base) {
  const findings = runSecretScan(htmlBody, "index.html");

  const jsUrls = [];
  const scriptRx = /<script[^>]+src=["']([^"']+)["']/gi;
  let sm;
  while ((sm = scriptRx.exec(htmlBody)) !== null) {
    const src = sm[1];
    const abs = src.startsWith("http") ? src : base.replace(/\/$/, "") + (src.startsWith("/") ? src : "/" + src);
    if (abs.includes(".js")) jsUrls.push(abs);
  }

  const toScan = jsUrls.slice(0, 6);
  await Promise.all(toScan.map(async (jsUrl) => {
    const r = await fetchReq(jsUrl, "GET", {}, 8000);
    if (!r.ok || !r.body) return;
    const fname = jsUrl.split("/").pop().split("?")[0] || "script.js";
    findings.push(...runSecretScan(r.body, fname));
  }));

  return { findings, jsFilesScanned: toScan.length, jsUrls: toScan };
}

// ─── CORS origin bypass test ──────────────────────────────────────────────────
async function testCORS(baseUrl, hostname) {
  const origins = [
    "https://evil.com",
    "null",
    `https://${hostname}.evil.com`,
    "https://attacker.com",
    `https://evil.${hostname}`,
  ];

  const results = await Promise.all(origins.map(async (origin) => {
    const r = await fetchReq(baseUrl, "GET", { "Origin": origin }, 5000);
    const acao = r.headers?.["access-control-allow-origin"] || null;
    const acac = r.headers?.["access-control-allow-credentials"] || null;
    return {
      origin,
      reflected: acao === origin,
      wildcard: acao === "*",
      allowCredentials: acac === "true",
      acao,
    };
  }));

  const vulnerable = results.filter(r => r.reflected || (r.wildcard && r.allowCredentials));
  return { results, vulnerable: vulnerable.length > 0, vulnerableOrigins: vulnerable };
}

// ─── Subdomain enumeration ────────────────────────────────────────────────────
function dnsResolveWithTimeout(hostname, timeoutMs = 3000) {
  return Promise.race([
    dns.promises.resolve4(hostname).catch(() => null),
    new Promise(resolve => setTimeout(() => resolve(null), timeoutMs)),
  ]);
}

async function checkSubdomains(hostname) {
  const COMMON = [
    "www","api","admin","dev","staging","test","mail","app",
    "backend","cdn","git","docs","wiki","beta","internal","status",
  ];

  const results = await Promise.all(COMMON.map(async (sub) => {
    const fqdn = `${sub}.${hostname}`;
    try {
      const addrs = await dnsResolveWithTimeout(fqdn, 2000);
      if (!addrs) return null;
      const r = await fetchReq(`https://${fqdn}/`, "HEAD", {}, 2000);
      return { sub: fqdn, ips: addrs, status: r.ok ? r.status : null };
    } catch { return null; }
  }));

  return results.filter(Boolean);
}

// ─── Open redirect test ───────────────────────────────────────────────────────
async function testOpenRedirect(base) {
  const params = ["redirect","url","next","return","returnUrl","goto","continue","dest","redir","return_url","callback","forward","location","target","link"];
  const payload = "https://evil.com/";

  const results = await Promise.all(params.map(async (param) => {
    const testUrl = `${base}/?${param}=${encodeURIComponent(payload)}`;
    const r = await fetchReq(testUrl, "GET", {}, 4000);
    const loc = r.headers?.location || "";
    const vulnerable = r.status >= 300 && r.status < 400 && loc.includes("evil.com");
    return { param, status: r.status, location: loc || null, vulnerable };
  }));

  const vuln = results.filter(r => r.vulnerable);
  return { tested: params.length, vulnerable: vuln.length > 0, params: vuln };
}

// ─── Technology fingerprint ───────────────────────────────────────────────────
function detectTech(headers, body) {
  const techs = [];
  const h = headers || {};
  const b = (body || "").toLowerCase();

  if (h["server"])       techs.push({ tech: h["server"],       cat: "Server" });
  if (h["x-powered-by"]) techs.push({ tech: h["x-powered-by"], cat: "Framework" });

  if (b.includes("wp-content") || b.includes("wp-includes")) techs.push({ tech: "WordPress",  cat: "CMS" });
  if (b.includes("/sites/default/files"))                     techs.push({ tech: "Drupal",     cat: "CMS" });
  if (b.includes("joomla"))                                   techs.push({ tech: "Joomla",     cat: "CMS" });

  if (b.includes("_next/static") || b.includes("__next"))     techs.push({ tech: "Next.js",    cat: "Framework" });
  if (b.includes("__nuxt") || b.includes("nuxt"))             techs.push({ tech: "Nuxt.js",    cat: "Framework" });
  if (b.includes("ng-version") || b.includes("angular"))      techs.push({ tech: "Angular",    cat: "Framework" });
  if (b.includes("data-reactroot") || b.includes("react"))    techs.push({ tech: "React",      cat: "Library" });
  if (b.includes("__vue__") || b.includes("vue.js"))          techs.push({ tech: "Vue.js",     cat: "Framework" });
  if (b.includes("laravel_session") || b.includes("laravel")) techs.push({ tech: "Laravel",    cat: "Framework" });
  if (b.includes("csrfmiddlewaretoken"))                       techs.push({ tech: "Django",     cat: "Framework" });
  if (b.includes("rails") || h["x-runtime"])                  techs.push({ tech: "Ruby on Rails", cat: "Framework" });

  if (h["cf-ray"])           techs.push({ tech: "Cloudflare",    cat: "CDN" });
  if (h["x-vercel-id"])      techs.push({ tech: "Vercel",        cat: "Hosting" });
  if (h["x-amzn-requestid"]) techs.push({ tech: "AWS",           cat: "Cloud" });
  if (h["x-azure-ref"])      techs.push({ tech: "Azure",         cat: "Cloud" });

  if (b.includes("gtag(") || b.includes("google-analytics")) techs.push({ tech: "Google Analytics", cat: "Analytics" });
  if (b.includes("segment.io"))                               techs.push({ tech: "Segment",          cat: "Analytics" });

  return techs;
}

// ─── Main probe endpoint ─────────────────────────────────────────────────────
app.get("/api/probe", async (req, res) => {
  let { target } = req.query;
  if (!target) return res.status(400).json({ error: "target required" });
  if (!target.startsWith("http")) target = "https://" + target;

  let hostname;
  try { hostname = new URL(target).hostname; }
  catch { return res.status(400).json({ error: "URL inválida" }); }

  const base = `https://${hostname}`;
  console.log(`\n[SCAN START] ${hostname} — ${new Date().toISOString()}`);

  // hard timeout — respond after 55s with whatever we have
  const scanTimeout = new Promise(resolve => setTimeout(() => resolve("TIMEOUT"), 90000));

  async function runScan() {
  const t0 = Date.now();
  const lap = (label) => console.log(`  [${label}] ${Date.now()-t0}ms`);

  // Phase 1 — all parallel probes
  // Phase 1a — lightweight probes (fast, don't spam the target)
  const [
    getResult,
    sslResult,
    dnsResult,
    httpRedirect,
    portScan,
    slowloris,
    subdomains,
  ] = await Promise.all([
    fetchReq(target, "GET", {}, 10000).then(r => { lap("GET"); return r; }),
    checkSSL(hostname).then(r => { lap("SSL"); return r; }),
    checkDNS(hostname).then(r => { lap("DNS"); return r; }),
    fetchReq(`http://${hostname}/`, "GET", {}, 6000).then(r => { lap("HTTP"); return r; }),
    scanPorts(hostname).then(r => { lap("PORTS"); return r; }),
    testSlowloris(hostname, 443).then(r => { lap("SLOWLORIS"); return r; }),
    checkSubdomains(hostname).then(r => { lap("SUBDOMAINS"); return r; }),
  ]);
  lap("PHASE1a DONE");

  // Phase 1b — heavier probes (separated to avoid triggering rate limits)
  const [pathsResult, httpMethods, rateLimit, corsTest, openRedirect] = await Promise.all([
    checkPaths(base).then(r => { lap("PATHS"); return r; }),
    checkMethods(target).then(r => { lap("METHODS"); return r; }),
    testRateLimit(base, "/", 15).then(r => { lap("RATELIMIT"); return r; }),
    testCORS(base, hostname).then(r => { lap("CORS"); return r; }),
    testOpenRedirect(base).then(r => { lap("OPENREDIRECT"); return r; }),
  ]);
  lap("PHASE1b DONE");

  // Phase 2 — depends on getResult.body
  const [jsSecrets, techStack] = await Promise.all([
    scanJsSecrets(getResult.body || "", base),
    Promise.resolve(detectTech(getResult.headers || {}, getResult.body || "")),
  ]);
  lap("PHASE2 DONE");

  const h = getResult.headers || {};

  // classify exposed paths
  const exposed   = Object.entries(pathsResult).filter(([, s]) => s && s < 400 && s !== 404);
  const forbidden = Object.entries(pathsResult).filter(([, s]) => s === 403 || s === 401);
  const openPorts = portScan.filter(p => p.open);

  const report = {
    hostname,
    url: target,
    timestamp: new Date().toISOString(),

    http: {
      status: getResult.status,
      reachable: getResult.ok,
      server:    h["server"] || null,
      poweredBy: h["x-powered-by"] || null,
      via:       h["via"] || null,
      cf_ray:    h["cf-ray"] || null,          // Cloudflare indicator
      x_vercel:  h["x-vercel-id"] || null,    // Vercel indicator
    },

    cdn: {
      cloudflare: !!(h["cf-ray"] || h["cf-cache-status"]),
      vercel:     !!(h["x-vercel-id"] || h["x-vercel-cache"]),
      fastly:     !!(h["x-served-by"] && h["x-served-by"].includes("cache")),
      detected:   h["cf-ray"] ? "Cloudflare" : h["x-vercel-id"] ? "Vercel" : h["x-served-by"] ? "Fastly" : "Não detetado",
    },

    headers: {
      hsts:               h["strict-transport-security"] || null,
      csp:                h["content-security-policy"] || null,
      xFrameOptions:      h["x-frame-options"] || null,
      xContentTypeOptions:h["x-content-type-options"] || null,
      referrerPolicy:     h["referrer-policy"] || null,
      permissionsPolicy:  h["permissions-policy"] || null,
      corsOrigin:         h["access-control-allow-origin"] || null,
      cacheControl:       h["cache-control"] || null,
      setCookie:          h["set-cookie"] || null,
    },

    ssl: sslResult,

    redirect: {
      httpStatus: httpRedirect.status,
      redirectsToHTTPS: httpRedirect.status >= 300 && httpRedirect.status < 400
        && (httpRedirect.headers?.location || "").startsWith("https"),
      location: httpRedirect.headers?.location || null,
    },

    dns: dnsResult,

    ports: {
      open: openPorts.map(p => ({ port: p.port, svc: p.svc })),
      scanned: portScan.length,
      dangerous: openPorts.filter(p =>
        [21,23,2375,2376,3306,5432,6379,8888,9090,9200,11211,27017,6443].includes(p.port)
      ).map(p => ({ port: p.port, svc: p.svc })),
    },

    paths: {
      exposed:   exposed.map(([p, s]) => ({ path: p, status: s })),
      forbidden: forbidden.map(([p, s]) => ({ path: p, status: s })),
      all: pathsResult,
    },

    rateLimit: {
      tested: rateLimit.sent,
      statuses: rateLimit.unique,
      rateLimited: rateLimit.rateLimited,
      has429: rateLimit.has429,
    },

    httpMethods: httpMethods,

    slowloris: slowloris,

    jsSecrets: {
      found: jsSecrets.findings.length > 0,
      count: jsSecrets.findings.length,
      findings: jsSecrets.findings,
      jsFilesScanned: jsSecrets.jsFilesScanned,
    },

    cors: corsTest,

    subdomains: {
      found: subdomains,
      count: subdomains.length,
      sensitive: subdomains.filter(s =>
        /admin|dev|staging|test|internal|intranet|corp|db|sql|redis|mongo|kibana|grafana|jenkins/.test(s.sub)
      ),
    },

    openRedirect: openRedirect,

    techStack: techStack,

    body_snippet: getResult.body ? getResult.body.slice(0, 3000) : null,
  };

    console.log(`[SCAN DONE] ${hostname} — ports: ${openPorts.length} open, paths: ${exposed.length} exposed, subdomains: ${subdomains.length}, secrets: ${jsSecrets.findings.length}`);
    return report;
  } // end runScan

  const result = await Promise.race([runScan(), scanTimeout]);
  if (result === "TIMEOUT") {
    console.log(`[SCAN TIMEOUT] ${hostname}`);
    return res.status(408).json({ error: "Scan timeout — alvo demorou demasiado a responder" });
  }
  res.json(result);
});

// ─── Claude AI analysis endpoint ─────────────────────────────────────────────
app.post("/api/analyze", async (req, res) => {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey || apiKey.includes("COLOCA_AQUI")) {
    return res.status(500).json({ error: "ANTHROPIC_API_KEY não configurada no .env" });
  }

  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error: "prompt required" });

  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-6",
        max_tokens: 8192,
        messages: [{ role: "user", content: prompt }],
      }),
    });

    const data = await response.json();
    if (data.error) return res.status(400).json({ error: data.error.message });
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(3001, () => {
  console.log("╔══════════════════════════════════════════╗");
  console.log("║  INC ZeroDay Shield — Scanner Backend    ║");
  console.log("║  http://localhost:3001                   ║");
  console.log("╚══════════════════════════════════════════╝");
});
