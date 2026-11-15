const express = require("express");
const Database = require("better-sqlite3");
const { Pool } = require("pg");
const path = require("path");
const multer = require("multer");

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

const PORT = process.env.PORT || 3000;
const app = express();

/* ==================== DATABASE ==================== */
// Production (Vercel): set DATABASE_URL to a Neon PostgreSQL connection string.
// Development: SQLite remains convenient and requires no account or configuration.
const usingPostgres = Boolean(process.env.DATABASE_URL);
const pool = usingPostgres ? new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : undefined
}) : null;
const db = usingPostgres ? null : new Database(path.join(__dirname, "cybershield.db"));

function postgresSql(sql) {
  let index = 0;
  return sql.replace(/\?/g, () => `$${++index}`);
}
async function all(sql, params = []) {
  if (pool) return (await pool.query(postgresSql(sql), params)).rows;
  return db.prepare(sql).all(...params);
}
async function get(sql, params = []) {
  if (pool) return (await pool.query(postgresSql(sql), params)).rows[0];
  return db.prepare(sql).get(...params);
}
async function run(sql, params = []) {
  if (pool) {
    const result = await pool.query(`${postgresSql(sql)} RETURNING id`, params);
    return { lastInsertRowid: result.rows[0]?.id };
  }
  return db.prepare(sql).run(...params);
}

async function initializeDatabase() {
  if (pool) {
    await pool.query(`CREATE TABLE IF NOT EXISTS signatures (
      id SERIAL PRIMARY KEY, sig TEXT NOT NULL UNIQUE, type TEXT NOT NULL, sev TEXT NOT NULL
    ); CREATE TABLE IF NOT EXISTS runs (
      id SERIAL PRIMARY KEY, kind TEXT NOT NULL, summary TEXT NOT NULL, input TEXT NOT NULL,
      result TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    );`);
  } else {
    db.pragma("journal_mode = WAL");
    db.exec(`CREATE TABLE IF NOT EXISTS signatures (
      id INTEGER PRIMARY KEY AUTOINCREMENT, sig TEXT NOT NULL UNIQUE, type TEXT NOT NULL, sev TEXT NOT NULL
    ); CREATE TABLE IF NOT EXISTS runs (
      id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, summary TEXT NOT NULL, input TEXT NOT NULL,
      result TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
    );`);
  }
  const count = await get("SELECT COUNT(*) AS c FROM signatures");
  if (Number(count.c) === 0) {
    for (const signature of [["' or '1'='1", "SQL Injection", "High"], ["union select", "SQL Injection", "High"], ["drop table", "SQL Injection", "Critical"], ["<script>", "XSS", "High"], ["../", "Path Traversal", "High"], ["cmd.exe", "Command Injection", "Critical"]]) {
      await run("INSERT INTO signatures (sig, type, sev) VALUES (?, ?, ?)", signature);
    }
  }
}
const databaseReady = initializeDatabase();
async function record(kind, summary, input, result) {
  const info = await run("INSERT INTO runs (kind, summary, input, result) VALUES (?, ?, ?, ?)", [kind, summary, JSON.stringify(input), JSON.stringify(result)]);
  return Number(info.lastInsertRowid);
}

/* ==================== ALGORITHMS ==================== */

// Naive matching. O(n*m) worst case.
function naiveSearch(text, pat) {
  const pos = [];
  let comps = 0;
  const n = text.length, m = pat.length;
  if (m === 0 || m > n) return { positions: pos, comparisons: 0 };
  for (let i = 0; i <= n - m; i++) {
    let j = 0;
    while (j < m) {
      comps++;
      if (text[i + j] !== pat[j]) break;
      j++;
    }
    if (j === m) pos.push(i);
  }
  return { positions: pos, comparisons: comps };
}

// KMP failure table. O(m)
function buildLPS(p) {
  const lps = new Array(p.length).fill(0);
  let len = 0, i = 1;
  while (i < p.length) {
    if (p[i] === p[len]) { len++; lps[i] = len; i++; }
    else if (len) { len = lps[len - 1]; }
    else { lps[i] = 0; i++; }
  }
  return lps;
}

// KMP search. O(n + m). Never re-checks text characters.
function kmpSearch(text, pat) {
  const pos = [];
  let comps = 0;
  if (pat.length === 0 || pat.length > text.length) return { positions: pos, comparisons: 0 };
  const lps = buildLPS(pat);
  let i = 0, j = 0;
  while (i < text.length) {
    comps++;
    if (text[i] === pat[j]) {
      i++; j++;
      if (j === pat.length) { pos.push(i - j); j = lps[j - 1]; }
    } else if (j) {
      j = lps[j - 1];
    } else {
      i++;
    }
  }
  return { positions: pos, comparisons: comps };
}

// Rabin-Karp with rolling hash. Average O(n + m). Hash matches are verified character by character.
function rabinKarpSearch(text, pat) {
  const d = 256, q = 101;
  const n = text.length, m = pat.length;
  const pos = [];
  let comps = 0;
  if (m === 0 || m > n) return { positions: pos, comparisons: 0 };
  let h = 1;
  for (let i = 0; i < m - 1; i++) h = (h * d) % q;
  let p = 0, t = 0;
  for (let i = 0; i < m; i++) {
    p = (d * p + pat.charCodeAt(i)) % q;
    t = (d * t + text.charCodeAt(i)) % q;
  }
  for (let i = 0; i <= n - m; i++) {
    comps++;
    if (p === t) {
      let k = 0;
      while (k < m) {
        comps++;
        if (text[i + k] !== pat[k]) break;
        k++;
      }
      if (k === m) pos.push(i);
    }
    if (i < n - m) {
      t = ((d * (t - text.charCodeAt(i) * h)) % q + q) % q;
      t = (t + text.charCodeAt(i + m)) % q;
    }
  }
  return { positions: pos, comparisons: comps };
}

// Edmonds-Karp max flow: BFS finds the shortest augmenting path each round.
function edmondsKarpMaxFlow(links, sName, tName) {
  const names = [];
  const idx = {};
  const add = name => { if (!(name in idx)) { idx[name] = names.length; names.push(name); } };
  add(sName); add(tName);
  links.forEach(l => { add(l.from); add(l.to); });
  const N = names.length;
  const cap = Array.from({ length: N }, () => new Array(N).fill(0));
  links.forEach(l => {
    const u = idx[l.from], v = idx[l.to], c = Number(l.cap) || 0;
    if (u !== v && c > 0) cap[u][v] += c;
  });
  const res = cap.map(r => r.slice());
  const s = idx[sName], t = idx[tName];
  let total = 0;
  const paths = [];
  if (s === t) return { value: 0, paths, edges: [], names };

  while (true) {
    const parent = new Array(N).fill(-1);
    parent[s] = s;
    const queue = [s];
    while (queue.length && parent[t] === -1) {
      const u = queue.shift();
      for (let v = 0; v < N; v++) {
        if (parent[v] === -1 && res[u][v] > 0) { parent[v] = u; queue.push(v); }
      }
    }
    if (parent[t] === -1) break;
    let bottleneck = Infinity;
    for (let v = t; v !== s; v = parent[v]) bottleneck = Math.min(bottleneck, res[parent[v]][v]);
    const nodes = [];
    for (let v = t; v !== s; v = parent[v]) {
      res[parent[v]][v] -= bottleneck;
      res[v][parent[v]] += bottleneck;
      nodes.unshift(names[v]);
    }
    nodes.unshift(names[s]);
    total += bottleneck;
    paths.push({ route: nodes.join(" -> "), bottleneck });
  }

  const edges = links.map(l => {
    const u = idx[l.from], v = idx[l.to];
    return { from: l.from, to: l.to, cap: Number(l.cap) || 0, flow: Math.max(0, cap[u][v] - res[u][v]) };
  });
  return { value: total, paths, edges, names };
}

// Resource allocation: largest stream first, to the least-loaded server that still fits it.
function balanceLoad(loads, servers, cap) {
  const used = new Array(servers).fill(0);
  const assign = new Array(loads.length).fill(-1);
  loads.map((l, i) => ({ i, l })).sort((a, b) => b.l - a.l).forEach(({ i, l }) => {
    let best = -1;
    for (let s = 0; s < servers; s++) {
      if (used[s] + l <= cap && (best === -1 || used[s] < used[best])) best = s;
    }
    if (best !== -1) { used[best] += l; assign[i] = best; }
  });
  return { used, assign };
}

/* ==================== MIDDLEWARE ==================== */
app.use(express.json({ limit: "50mb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use(async (req, res, next) => {
  try { await databaseReady; next(); }
  catch (error) { next(error); }
});

/* ==================== SIGNATURES API ==================== */
app.get("/api/signatures", async (req, res) => {
  res.json(await all("SELECT * FROM signatures ORDER BY id"));
});

app.post("/api/signatures", async (req, res) => {
  const sig = String(req.body.sig || "").trim().toLowerCase();
  if (!sig) return res.status(400).json({ error: "Signature is required" });
  const type = String(req.body.type || "Custom");
  const sev = ["Low", "Medium", "High", "Critical"].includes(req.body.sev) ? req.body.sev : "High";
  try {
    const info = await run("INSERT INTO signatures (sig, type, sev) VALUES (?, ?, ?)", [sig, type, sev]);
    res.json({ id: Number(info.lastInsertRowid), sig, type, sev });
  } catch (e) {
    res.status(409).json({ error: "This signature already exists" });
  }
});

app.delete("/api/signatures/:id", async (req, res) => {
  await run("DELETE FROM signatures WHERE id = ?", [req.params.id]);
  res.json({ ok: true });
});

/* ==================== PAGE 1: SCANNER ==================== */
app.post("/api/scan", async (req, res) => {
  const log = String(req.body.log || "");
  const signatures = await all("SELECT * FROM signatures ORDER BY id");
  const rows = [];
  let total = 0, threatLines = 0;

  log.split("\n").forEach((line, idx) => {
    if (!line.trim()) return;
    total++;
    const low = line.toLowerCase();
    let hit = false;
    signatures.forEach(s => {
      const useKMP = s.sig.length < 10;
      const r = useKMP ? kmpSearch(low, s.sig) : rabinKarpSearch(low, s.sig);
      if (r.positions.length > 0) {
        hit = true;
        rows.push({ line: idx + 1, log: line, type: s.type, sig: s.sig, algorithm: useKMP ? "KMP" : "Rabin-Karp", severity: s.sev });
      }
    });
    if (hit) threatLines++;
  });

  const result = { total, threatLines, safe: total - threatLines, rows };
  const id = await record("scan", `${threatLines} threat line(s) out of ${total}`, { log: log.slice(0, 5000), lines: total }, result);
  res.json({ id, ...result });
});

/* ==================== PAGE 2: DNA MOTIF ==================== */
app.post("/api/dna", async (req, res) => {
  const sequence = String(req.body.sequence || "").toUpperCase().replace(/[^ACGT]/g, "");
  const motif = String(req.body.motif || "").toUpperCase().replace(/[^ACGT]/g, "");
  if (!motif) return res.status(400).json({ error: "Enter a motif made of A, C, G, T" });
  if (motif.length > sequence.length) return res.status(400).json({ error: "Motif is longer than the sequence" });

  const r = naiveSearch(sequence, motif);
  const result = { sequence, motif, positions: r.positions, comparisons: r.comparisons };
  const id = await record("dna", `Motif ${motif}: ${r.positions.length} match(es)`, { sequence, motif }, result);
  res.json({ id, ...result });
});

/* ==================== PAGE 3: BANDWIDTH ==================== */
app.post("/api/flow", async (req, res) => {
  const links = Array.isArray(req.body.links) ? req.body.links : [];
  const source = String(req.body.source || "");
  const sink = String(req.body.sink || "");
  if (!source || !sink) return res.status(400).json({ error: "Choose a source and a client" });

  const clean = links
    .map(l => ({ from: String(l.from || "").trim(), to: String(l.to || "").trim(), cap: Number(l.cap) || 0 }))
    .filter(l => l.from && l.to);
  const r = edmondsKarpMaxFlow(clean, source, sink);
  const id = await record("flow", `Max flow ${source} to ${sink}: ${r.value} Mbps`, { links: clean, source, sink }, r);
  res.json({ id, ...r });
});

/* ==================== PAGE 4: LOAD BALANCER ==================== */
app.post("/api/balance", async (req, res) => {
  const servers = parseInt(req.body.servers, 10);
  const cap = Number(req.body.capacity);
  const loads = Array.isArray(req.body.loads) ? req.body.loads.map(Number).filter(x => x > 0) : [];
  if (!(servers >= 1) || !(cap > 0) || loads.length === 0) {
    return res.status(400).json({ error: "Enter at least 1 server, a capacity above 0, and some loads" });
  }

  const { used, assign } = balanceLoad(loads, servers, cap);
  const utils = used.map(u => (u / cap) * 100);
  const result = {
    loads,
    total: loads.reduce((a, b) => a + b, 0),
    servers: used.map((u, i) => ({ id: i + 1, used: u, utilization: utils[i] })),
    assignments: loads.map((l, i) => ({ stream: i + 1, load: l, server: assign[i] === -1 ? null : assign[i] + 1 })),
    averageUtilization: utils.reduce((a, b) => a + b, 0) / utils.length,
    imbalance: Math.max(...utils) - Math.min(...utils)
  };
  const id = await record("balance", `${loads.length} streams on ${servers} servers`, { servers, capacity: cap, loads }, result);
  res.json({ id, ...result });
});

/* ==================== PAGE 5: COMPARISON ==================== */
app.post("/api/compare", async (req, res) => {
  const text = String(req.body.text || "").toLowerCase();
  const pattern = String(req.body.pattern || "").toLowerCase();
  if (!pattern) return res.status(400).json({ error: "Enter a pattern" });

  const REPS = 200;
  const algos = [["Naive", naiveSearch], ["KMP", kmpSearch], ["Rabin-Karp", rabinKarpSearch]];
  const rows = algos.map(([name, fn]) => {
    const r = fn(text, pattern);
    const t0 = process.hrtime.bigint();
    for (let k = 0; k < REPS; k++) fn(text, pattern);
    const ms = Number(process.hrtime.bigint() - t0) / 1e6 / REPS;
    return { algorithm: name, comparisons: r.comparisons, timeMs: Number(ms.toFixed(4)), matches: r.positions.length };
  });
  const id = await record("compare", `Pattern "${pattern}" on ${text.length} characters`, { text, pattern }, { rows });
  res.json({ id, rows });
});

/* ==================== HISTORY API ==================== */
app.get("/api/runs", async (req, res) => {
  const kind = req.query.kind;
  const rows = kind
    ? await all("SELECT id, kind, summary, created_at FROM runs WHERE kind = ? ORDER BY id DESC LIMIT 200", [kind])
    : await all("SELECT id, kind, summary, created_at FROM runs ORDER BY id DESC LIMIT 200");
  res.json(rows);
});

app.get("/api/runs/:id", async (req, res) => {
  const row = await get("SELECT * FROM runs WHERE id = ?", [req.params.id]);
  if (!row) return res.status(404).json({ error: "Not found" });
  res.json({ ...row, input: JSON.parse(row.input), result: JSON.parse(row.result) });
});

app.delete("/api/runs", async (req, res) => {
  await run("DELETE FROM runs");
  res.json({ ok: true });
});

/* ==================== FILE UPLOAD: TEXT, PDF, PHOTO ==================== */
// Turns an uploaded file into plain text that the input box can use.
app.post("/api/extract", upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });
  const name = req.file.originalname;
  const ext = path.extname(name).toLowerCase();
  try {
    let text, method;
    if ([".txt", ".log", ".csv", ".fa", ".fasta", ".json", ".md"].includes(ext)) {
      text = req.file.buffer.toString("utf8");
      method = "text file";
    } else if (ext === ".pdf") {
      const pdfParse = require("pdf-parse");
      text = (await pdfParse(req.file.buffer)).text;
      method = "PDF text";
    } else if ([".png", ".jpg", ".jpeg", ".webp", ".bmp"].includes(ext)) {
      const { createWorker } = require("tesseract.js");
      const worker = await createWorker("eng");
      const { data } = await worker.recognize(req.file.buffer);
      await worker.terminate();
      text = data.text;
      method = "text read from photo (OCR)";
    } else {
      return res.status(400).json({ error: "Unsupported file type. Use .txt, .log, .csv, .fasta, .pdf, or a photo (.png, .jpg)." });
    }
    res.json({ name, method, text: text.trim() });
  } catch (e) {
    res.status(500).json({ error: "Could not read this file: " + e.message });
  }
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`CyberShield IDS running at http://localhost:${PORT}`);
  });
}

module.exports = app;
