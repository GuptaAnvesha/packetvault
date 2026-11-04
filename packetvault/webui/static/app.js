"use strict";

// ====================================================================== basics
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = (n, d = 0) => (n == null || Number.isNaN(n) ? "–" : Number(n).toLocaleString(undefined, { maximumFractionDigits: d, minimumFractionDigits: d }));
const tick = (n) => Number(n).toLocaleString(undefined, { maximumFractionDigits: 2 });
const num = (n) => (Number.isInteger(n) ? fmt(n) : fmt(n, n < 10 ? 2 : n < 100 ? 1 : 0));
const kib = (b) => (b >= 1048576 ? fmt(b / 1048576, 1) + " MiB" : fmt(b / 1024, 1) + " KiB");
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const short = (h, n = 16) => (h ? h.slice(0, n) + "…" : "–");
const clock = (t) => new Date(t * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });

async function api(path, body) {
  const opts = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({ error: res.statusText }));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

let toastTimer;
function toast(msg, error = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (error ? " error" : "");
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), error ? 7000 : 3500);
}

// Run an async action with the button disabled and errors toasted.
async function act(btn, fn, busyText) {
  const label = btn?.textContent;
  if (btn) { btn.disabled = true; if (busyText) btn.textContent = busyText; }
  try { return await fn(); } catch (e) { toast(e.message, true); } finally { if (btn) { btn.disabled = false; btn.textContent = label; } }
}

const passphrase = () => $("#passphrase").value;
function needPass() {
  if (passphrase().length < 8) { toast("Enter the case passphrase (Cases tab, 8+ characters).", true); return false; }
  return true;
}

// ====================================================================== tabs
let activeTab = "overview";
function showTab(name) {
  $$(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  $$(".panel").forEach((p) => p.classList.toggle("active", p.id === "tab-" + name));
  activeTab = name;
  history.replaceState(null, "", "#" + name);
  ({ overview: loadOverview, acquire: loadCaptures, nmap: loadInterfaces, cases: loadCases, security: loadSecurity, nmac: () => { if (!$("#nmac-flow").children.length) computeNmac(); } }[name] || (() => {}))();
}
$$(".tab").forEach((t) => t.addEventListener("click", () => showTab(t.dataset.tab)));

// ====================================================================== charts
const SVGNS = "http://www.w3.org/2000/svg";
const tip = $("#tooltip");
function showTip(e, html) {
  tip.innerHTML = html; tip.hidden = false;
  const w = tip.offsetWidth, h = tip.offsetHeight;
  let x = e.clientX + 14, y = e.clientY + 14;
  if (x + w > innerWidth - 8) x = e.clientX - w - 14;
  if (y + h > innerHeight - 8) y = e.clientY - h - 14;
  tip.style.left = x + "px"; tip.style.top = y + "px";
}
const hideTip = () => (tip.hidden = true);
const tipRow = (c, l, v) => `<div class="row"><span>${c ? `<i style="background:${c}"></i>` : ""}${esc(l)}</span><b>${esc(v)}</b></div>`;
function el(tag, attrs, parent) {
  const n = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  parent?.appendChild(n);
  return n;
}
function txt(parent, x, y, s, attrs = {}) { const t = el("text", { x, y, ...attrs }, parent); t.textContent = s; return t; }
function niceMax(v) { if (v <= 0) return 1; const p = 10 ** Math.floor(Math.log10(v)); const m = v / p; return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p; }
function svgFrame(c, height) {
  c.innerHTML = "";
  const width = Math.max(c.clientWidth, 300);
  return { svg: el("svg", { viewBox: `0 0 ${width} ${height}`, height, role: "img" }, c), width, height };
}
function legend(target, items) { $(target).innerHTML = items.map(([c, l]) => `<span><i style="background:${c}"></i>${esc(l)}</span>`).join(""); }

// Horizontal bars: rows = [{label, value, color, tip}]
function hbars(c, rows, unit = "", labelW = 130) {
  if (!rows.length) { c.innerHTML = '<p class="muted small-text">No data yet.</p>'; return; }
  const rowH = 24, f = svgFrame(c, rows.length * rowH + 6), x0 = labelW, x1 = f.width - 70;
  const max = niceMax(Math.max(...rows.map((r) => r.value)));
  rows.forEach((r, i) => {
    const y = 3 + i * rowH, w = Math.max((r.value / max) * (x1 - x0), r.value > 0 ? 2 : 0);
    txt(f.svg, x0 - 8, y + 15, r.label, { "text-anchor": "end", class: "label" });
    if (w) el("path", { d: `M${x0},${y + 4}H${x0 + w - Math.min(4, w)}Q${x0 + w},${y + 4} ${x0 + w},${y + 8}V${y + 16}Q${x0 + w},${y + 20} ${x0 + w - Math.min(4, w)},${y + 20}H${x0}Z`, fill: r.color || css("--series-1") }, f.svg);
    txt(f.svg, x0 + w + 6, y + 15, num(r.value) + unit, { class: "value" });
    const hit = el("rect", { x: 0, y, width: f.width, height: rowH, fill: "transparent" }, f.svg);
    hit.addEventListener("mousemove", (e) => showTip(e, r.tip || tipRow(r.color || css("--series-1"), r.label, fmt(r.value, 2) + unit)));
    hit.addEventListener("mouseleave", hideTip);
  });
  el("line", { x1: x0, x2: x0, y1: 0, y2: f.height, class: "baseline" }, f.svg);
}

// Multi-series line chart: xs = labels, series = [{name, color, values}]
function lines(c, xs, series, { unit = "", height = 200, xfmt = (x) => x, xticks = 6 } = {}) {
  if (!xs.length) { c.innerHTML = '<p class="muted small-text">No data yet.</p>'; return; }
  const f = svgFrame(c, height), x0 = 52, x1 = f.width - 12, y0 = 8, y1 = height - 24;
  const max = niceMax(Math.max(...series.flatMap((s) => s.values)) * 1.05);
  const g = el("g", { class: "grid" }, f.svg);
  for (let i = 0; i <= 4; i++) {
    const y = y1 - (i / 4) * (y1 - y0);
    if (i) el("line", { x1: x0, x2: x1, y1: y, y2: y }, g);
    txt(f.svg, x0 - 6, y + 4, tick((max * i) / 4), { "text-anchor": "end" });
  }
  el("line", { x1: x0, x2: x1, y1, y2: y1, class: "baseline" }, f.svg);
  const sx = (i) => x0 + (xs.length === 1 ? (x1 - x0) / 2 : (i / (xs.length - 1)) * (x1 - x0));
  const sy = (v) => y1 - (v / max) * (y1 - y0);
  const step = Math.max(1, Math.ceil(xs.length / xticks));
  xs.forEach((x, i) => { if (i % step === 0 || i === xs.length - 1) txt(f.svg, sx(i), height - 6, xfmt(x), { "text-anchor": i === 0 ? "start" : i === xs.length - 1 ? "end" : "middle" }); });
  series.forEach((s) => {
    el("path", { d: s.values.map((v, i) => `${i ? "L" : "M"}${sx(i)},${sy(v)}`).join(""), fill: "none", stroke: s.color, "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round" }, f.svg);
    if (xs.length <= 12) s.values.forEach((v, i) => el("circle", { cx: sx(i), cy: sy(v), r: 4, fill: s.color, stroke: css("--surface-1"), "stroke-width": 2 }, f.svg));
  });
  const cross = el("line", { y1: y0, y2: y1, stroke: css("--axis"), visibility: "hidden" }, f.svg);
  const hit = el("rect", { x: x0, y: y0, width: x1 - x0, height: y1 - y0, fill: "transparent" }, f.svg);
  hit.addEventListener("mousemove", (e) => {
    const b = f.svg.getBoundingClientRect(), px = (e.clientX - b.left) * (f.width / b.width);
    const i = Math.max(0, Math.min(xs.length - 1, Math.round(((px - x0) / (x1 - x0)) * (xs.length - 1))));
    cross.setAttribute("x1", sx(i)); cross.setAttribute("x2", sx(i)); cross.setAttribute("visibility", "visible");
    showTip(e, `<div class="t">${esc(xfmt(xs[i], true))}</div>` + series.map((s) => tipRow(s.color, s.name, fmt(s.values[i], 2) + unit)).join(""));
  });
  hit.addEventListener("mouseleave", () => { hideTip(); cross.setAttribute("visibility", "hidden"); });
}

// Grouped vertical bars: groups = [{label, values:{key:v}}], keys = [[key, color, name]]
function groupedBars(c, groups, keys, unit = "") {
  const f = svgFrame(c, 220), x0 = 48, x1 = f.width - 10, y0 = 8, y1 = 196;
  const max = niceMax(Math.max(...groups.flatMap((g) => keys.map(([k]) => g.values[k]))) * 1.05);
  const grid = el("g", { class: "grid" }, f.svg);
  for (let i = 0; i <= 4; i++) { const y = y1 - (i / 4) * (y1 - y0); if (i) el("line", { x1: x0, x2: x1, y1: y, y2: y }, grid); txt(f.svg, x0 - 6, y + 4, tick((max * i) / 4), { "text-anchor": "end" }); }
  el("line", { x1: x0, x2: x1, y1, y2: y1, class: "baseline" }, f.svg);
  const gw = (x1 - x0) / groups.length, bw = Math.min(30, (gw - 20) / keys.length - 2);
  groups.forEach((g, i) => {
    const gx = x0 + i * gw + (gw - keys.length * (bw + 2)) / 2;
    keys.forEach(([k, color], j) => {
      const h = (g.values[k] / max) * (y1 - y0), x = gx + j * (bw + 2), r = Math.min(4, bw / 2, h);
      const p = el("path", { d: `M${x},${y1}V${y1 - h + r}Q${x},${y1 - h} ${x + r},${y1 - h}H${x + bw - r}Q${x + bw},${y1 - h} ${x + bw},${y1 - h + r}V${y1}Z`, fill: color }, f.svg);
      p.addEventListener("mousemove", (e) => showTip(e, `<div class="t">${esc(g.label)}</div>` + keys.map(([kk, cc, nn]) => tipRow(cc, nn, fmt(g.values[kk], 2) + unit)).join("")));
      p.addEventListener("mouseleave", hideTip);
    });
    txt(f.svg, x0 + i * gw + gw / 2, 214, g.label, { "text-anchor": "middle" });
  });
}

// ====================================================================== overview
async function loadTools(t) {
  const names = [["nmap", "Nmap"], ["dumpcap", "dumpcap"], ["tshark", "tshark"], ["wireshark", "Wireshark"], ["pyshark", "pyshark"]];
  $("#tool-chips").innerHTML = names.map(([k, l]) => `<span class="chip ${t[k] ? "on" : "off"}" title="${esc(t[k] === true ? "installed" : t[k] || "not installed: built-in fallback")}">${l}</span>`).join("");
  $("#nmap-tool").textContent = t.nmap ? "nmap: " + t.nmap : "nmap not installed: built-in TCP connect scanner";
  $("#live-tool").textContent = t.dumpcap || t.tshark ? "dumpcap found" : "needs Wireshark + Npcap";
  window.TOOLS = t;
}

const tile = (l, v, s) => `<div class="tile"><div class="l">${esc(l)}</div><div class="v">${v}</div><div class="s">${s || "&nbsp;"}</div></div>`;
const STAGES = [["parse", "M1 parse"], ["hash_chain", "M2 hash chain + NMAC"], ["encrypt", "M3 PBKDF2 + AES-GCM"], ["detect", "M4 detection"], ["report_and_sign", "M5 report + RSA sign"]];

async function loadOverview() {
  const o = await api("/api/overview");
  loadTools(o.tools);
  const t = o.totals;
  $("#tiles").innerHTML = [
    tile("Cases sealed", fmt(t.cases), `${fmt(t.keyed_cases)} with NMAC tags`),
    tile("Packets under seal", fmt(t.packets_sealed), `${fmt(t.captures)} captures in workspace`),
    tile("Scan alerts", fmt(t.alerts), "port-scan detector (M4)"),
    tile("Verifications", fmt(t.verifications), `${fmt(t.verify_fail)} detected tampering`),
    tile("Attack copies", fmt(t.tampered_copies), "tampered for demonstration"),
    tile("Nmap scans", fmt(t.scans), "from the Nmap tab"),
  ].join("");

  const seal = o.seals.at(-1);
  if (seal) {
    $("#seal-meta").textContent = `${seal.case_id} · ${fmt(seal.records)} packets · ${fmt(seal.total_ms)} ms total · PBKDF2 ${fmt(seal.kdf_iterations)}`;
    hbars($("#seal-chart"), STAGES.filter(([k]) => k in seal.timings).map(([k, l]) => ({ label: l, value: seal.timings[k] })), " ms", 160);
  } else $("#seal-chart").innerHTML = '<p class="muted small-text">Seal a capture in the Cases tab.</p>';

  const ver = o.verifies.at(-1);
  if (ver && ver.layers) {
    $("#verify-meta").textContent = `${ver.case_id} · ${ver.verdict} · ${fmt(ver.total_ms)} ms`;
    legend("#verify-legend", [[css("--series-1"), "layer passed"], [css("--critical"), "layer detected tampering"]]);
    hbars($("#verify-chart"), ver.layers.filter((c) => c.status !== "SKIP").map((c) => ({ label: c.name, value: c.ms, color: c.status === "PASS" ? css("--series-1") : css("--critical"),
      tip: tipRow(c.status === "PASS" ? css("--series-1") : css("--critical"), `${c.name} (${c.status})`, fmt(c.ms, 2) + " ms") })), " ms", 160);
  } else $("#verify-chart").innerHTML = '<p class="muted small-text">Verify a case in the Cases tab.</p>';

  renderBench(o.benchmarks);

  const k = o.keys;
  $("#keys-info").innerHTML = `<dt>Investigator RSA-2048</dt><dd>${k.investigator ? esc(k.investigator) : '<span class="status warn">not generated</span>'}</dd>
    <dt>Private key</dt><dd>${k.investigator ? (k.private_key_encrypted ? '<span class="status ok">passphrase-protected</span>' : '<span class="status warn">unencrypted PEM</span>') : "–"}</dd>
    <dt>Custodian NMAC key</dt><dd>${k.custodian ? esc(k.custodian) : '<span class="status warn">not generated</span>'}</dd>`;
  window.LAST_KEYS = k;
  $("#keygen").hidden = !!(k.investigator && k.custodian);
  $("#keygen").textContent = k.investigator ? "Generate custodian key" : "Generate keypair + custodian key";

  $("#events").innerHTML = o.events.map((e) => {
    const cls = e.kind === "verify" ? (e.verdict === "FAIL" ? "bad" : "good") : e.kind === "tamper" ? "bad" : "";
    return `<li class="${cls}"><time>${clock(e.ts)}</time><span class="tag">${esc(e.kind)}</span>${esc(describe(e))}</li>`;
  }).join("") || '<li class="muted">Nothing yet.</li>';
}

function describe(e) {
  switch (e.kind) {
    case "seal": return `${e.case_id}: ${fmt(e.records)} packets, ${e.alerts} alerts${e.keyed ? ", NMAC-tagged" : ""} (${fmt(e.total_ms)} ms)`;
    case "verify": return `${e.case_id}: ${e.verdict} (${fmt(e.total_ms)} ms)`;
    case "tamper": return `${e.mode} attack on frame ${e.index} → ${e.case_id}`;
    case "scan": return `${e.engine} scan of ${e.target}: ${e.open} open ports${e.capture ? ", captured to " + e.capture : ""}`;
    case "capture": return `${e.source}: ${e.file}`;
    case "matrix": return `tamper matrix on ${e.case_id}: ${e.detected}/${e.attacks} attacks detected`;
    case "keygen": return e.custodian ? "keys generated (incl. custodian NMAC key)" : "investigator keypair generated";
    case "bench": return `benchmarks re-run (${e.volumes.join(", ")} packets, ${e.total_s}s)`;
    default: return JSON.stringify(e);
  }
}

function renderBench(b) {
  if (!b) { $("#aes-chart").innerHTML = '<p class="muted small-text">No benchmark data.</p>'; return; }
  $("#bench-src").textContent = "source: " + b.source;
  const s3 = [css("--series-1"), css("--series-2"), css("--series-3")];
  const aesKeys = Object.keys(b.aes_modes), hashKeys = Object.keys(b.hashes);
  legend("#aes-legend", aesKeys.map((k, i) => [s3[i], "AES-" + k]));
  lines($("#aes-chart"), b.volumes, aesKeys.map((k, i) => ({ name: "AES-" + k, color: s3[i], values: b.aes_modes[k].map((p) => p.mb_per_s) })), { unit: " MB/s", xfmt: (v, long) => fmt(v) + (long ? " packets" : "") });
  legend("#hash-legend", hashKeys.map((k, i) => [s3[i], k]));
  lines($("#hash-chart"), b.volumes, hashKeys.map((k, i) => ({ name: k, color: s3[i], values: b.hashes[k].map((p) => p.us_per_record) })), { unit: " µs", xfmt: (v, long) => fmt(v) + (long ? " packets" : "") });
  const ops = b.rsa_vs_ecc.operations;
  $("#asym-table").innerHTML = `<thead><tr><th></th><th class="num">Key generation</th><th class="num">Sign</th><th class="num">Verify</th><th class="num">Signature</th></tr></thead><tbody>` +
    Object.entries(ops).map(([n, o]) => `<tr><td>${esc(n)}</td><td class="num">${fmt(o.keygen * 1000, 2)} ms</td><td class="num">${fmt(o.sign * 1000, 2)} ms</td><td class="num">${fmt(o.verify * 1000, 2)} ms</td><td class="num">${o.signature_bytes} B</td></tr>`).join("") + "</tbody>";
}

$("#bench-run").addEventListener("click", (e) => act(e.target, async () => { renderBench(await api("/api/bench", { volumes: "1000,5000,10000" })); toast("Benchmarks updated"); }, "Running…"));
$("#keygen").addEventListener("click", (e) => act(e.target, async () => {
  if (window.LAST_KEYS?.investigator) await api("/api/keys/custodian", {}); else await api("/api/keys", { custodian: true });
  toast("Keys generated in workspace/keys"); loadOverview();
}));

// ====================================================================== acquire
let currentCapture = null;
async function loadCaptures() {
  const c = await api("/api/captures");
  $("#cap-table tbody").innerHTML = c.files.map((f) => `<tr class="${f.file === currentCapture ? "sel" : ""}">
      <td class="mono">${esc(f.file)}</td><td class="num">${kib(f.bytes)}</td>
      <td>${f.labels ? `<span class="status ok">${esc(f.scanners.join(", ") || "labelled")}</span>` : '<span class="muted">none</span>'}</td>
      <td class="actions">
        <button class="ghost small" data-a="preview" data-f="${esc(f.file)}">Analyse</button>
        <button class="ghost small" data-a="seal" data-f="${esc(f.file)}">Seal…</button>
        <button class="ghost small" data-a="open" data-f="${esc(f.file)}" ${window.TOOLS?.wireshark ? "" : "disabled title='Wireshark not installed'"}>Wireshark</button>
        <a class="btn" href="/files/captures/${encodeURIComponent(f.file)}">Download</a>
        <button class="ghost small" data-a="delete" data-f="${esc(f.file)}">Delete</button>
      </td></tr>`).join("") || '<tr><td colspan="4" class="muted">No captures yet: generate, upload or capture one above.</td></tr>';
  $$("#cap-table [data-a]").forEach((b) => b.addEventListener("click", () => captureAction(b.dataset.a, b.dataset.f, b)));
  liveStatus(c.live);
  fillSelect($("#seal-file"), c.files.map((f) => f.file));
  if (!$("#iface").dataset.loaded) loadInterfaces();
  return c;
}

function fillSelect(sel, values, keep = true) {
  const cur = sel.value;
  sel.innerHTML = values.map((v) => `<option>${esc(v)}</option>`).join("");
  if (keep && values.includes(cur)) sel.value = cur;
}

async function loadInterfaces() {
  const { interfaces } = await api("/api/interfaces");
  const opts = interfaces.map((i) => `<option value="${esc(i.name)}">${esc(i.description)}</option>`).join("");
  $("#iface").innerHTML = opts || '<option value="">Wireshark/dumpcap not installed</option>';
  $("#iface").dataset.loaded = "1";
  const n = $("#nmap-iface"), cur = n.value;
  n.innerHTML = '<option value="">no capture</option>' + opts;
  n.value = cur;
}

function liveStatus(s) {
  const out = $("#live-status");
  $("#live-start").disabled = !!(s && s.running);
  if (!s) { out.textContent = ""; return; }
  out.innerHTML = s.running ? `● Capturing to <code>${esc(s.file)}</code> (${s.bytes ? kib(s.bytes) : "0 KiB"})…`
    : `Last capture: <code>${esc(s.file)}</code>${s.error ? ` <span class="status bad">${esc(s.error)}</span>` : ""}`;
  if (s.running) setTimeout(async () => { const c = await api("/api/captures"); liveStatus(c.live); if (!c.live?.running) loadCaptures(); }, 1500);
}

$("#live-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  act($("#live-start"), async () => { liveStatus(await api("/api/live/start", { interface: fd.get("interface"), filter: fd.get("filter"), seconds: +fd.get("seconds") })); });
});
$("#live-stop").addEventListener("click", (e) => act(e.target, async () => { await api("/api/live/stop", {}); loadCaptures(); }));

$("#upload-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const file = e.target.file.files[0];
  if (!file) return;
  act(e.target.querySelector("button"), async () => {
    const res = await fetch("/api/captures/upload?name=" + encodeURIComponent(file.name), { method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: file });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    $("#upload-status").textContent = `Uploaded ${data.file} (${kib(data.bytes)})` +
      (data.renamed_from ? `; ${data.renamed_from} already exists, so it was not overwritten` : "");
    e.target.reset();
    loadCaptures();
  }, "Uploading…");
});

$("#sample-form").addEventListener("submit", (e) => {
  e.preventDefault();
  act(e.target.querySelector("button"), async () => {
    const r = await api("/api/captures/sample", { seed: +new FormData(e.target).get("seed") });
    toast(`Generated ${r.file}: ${fmt(r.packets)} packets, scanners ${r.scanners.join(", ")}`);
    await loadCaptures();
    preview(r.file);
  }, "Generating…");
});

async function captureAction(a, file, btn) {
  if (a === "preview") return preview(file, btn);
  if (a === "seal") { showTab("cases"); $("#seal-file").value = file; $("#seal-form [name=case_id]").focus(); return; }
  if (a === "open") return act(btn, async () => toast("Opened: " + (await api("/api/captures/open", { file })).command));
  if (a === "delete" && confirm(`Delete capture ${file}?`)) return act(btn, async () => { await api("/api/captures/delete", { file }); if (currentCapture === file) $("#preview").hidden = true; loadCaptures(); });
}

const pvForm = $("#pv-form");
$("#pv-form").addEventListener("submit", (e) => { e.preventDefault(); preview(currentCapture, e.submitter); });
async function preview(file, btn) {
  currentCapture = file;
  const fd = new FormData(pvForm);
  await act(btn, async () => {
    const p = await api("/api/captures/preview", { file, backend: fd.get("backend"), threshold: +fd.get("threshold"), window: +fd.get("window") });
    renderPreview(p);
    loadCaptures();
  }, "Analysing…");
}

function renderPreview(p) {
  $("#preview").hidden = false;
  $("#cross-card").hidden = true;
  const st = p.statistics;
  $("#pv-title").textContent = `Analysis · ${p.file}`;
  $("#pv-tiles").innerHTML = [
    tile("Packets", fmt(st.packets), `${kib(st.bytes || 0)} on the wire`),
    tile("Duration", fmt(st.duration_seconds, 1) + " s", `${fmt(st.unique_hosts)} hosts`),
    tile("Parse speed", fmt(p.packets_per_s) + " pkt/s", `${p.backend} backend, ${fmt(p.parse_ms)} ms`),
    tile("Scan alerts", fmt(p.alerts.length), p.alerts.map((a) => a.src_ip).join(", ") || "none"),
    tile("Detection F1", p.evaluation ? fmt(p.evaluation.f1, 2) : "–", p.evaluation ? `precision ${fmt(p.evaluation.precision, 2)} · recall ${fmt(p.evaluation.recall, 2)}` : "add ground-truth labels"),
  ].join("");

  const tl = p.timeline;
  legend("#tl-legend", [[css("--series-1"), "All packets"], [css("--series-2"), "Connection probes (SYN without ACK)"]]);
  lines($("#tl-chart"), tl.map((b) => b.t), [{ name: "All packets", color: css("--series-1"), values: tl.map((b) => b.packets) },
    { name: "SYN probes", color: css("--series-2"), values: tl.map((b) => b.syn) }],
  { xfmt: (t, long) => new Date(t * 1000).toLocaleTimeString([], long ? {} : { minute: "2-digit", second: "2-digit" }) });
  hbars($("#proto-chart"), Object.entries(st.protocols || {}).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ label: k, value: v })), "", 90);
  hbars($("#talker-chart"), (st.top_talkers || []).map((t) => ({ label: t.ip, value: t.packets })), "", 130);

  $("#pv-alerts").innerHTML = p.alerts.length ? p.alerts.map((a) => `<div class="loc">
      <b>${esc(a.severity)}</b> ${esc(a.src_ip)} → ${esc(a.targets.join(", "))}<br>
      <span class="detail">${a.max_ports_in_window} distinct ports in one window · ${fmt(a.distinct_ports_total)} total · SYN:SYN-ACK ${a.syn_sent}:${a.synack_received} (ratio ${a.syn_ratio})</span></div>`).join("")
    : '<p><span class="status ok">No host crossed the threshold.</span></p>';
  $("#pv-hosts tbody").innerHTML = p.hosts.map((h) => `<tr><td>${esc(h.ip)}</td><td class="num">${fmt(h.probes)}</td><td class="num">${fmt(h.ports)}</td><td class="num">${fmt(h.max_ports_in_window)}</td><td class="num">${fmt(h.syn_ratio, 2)}</td></tr>`).join("") || '<tr><td colspan="5" class="muted">No probes.</td></tr>';

  const ev = p.evaluation;
  $("#pv-eval").innerHTML = ev ? `<dl class="kv">
      <dt>Ground truth scanners</dt><dd>${esc(p.labels.scanners.join(", "))}</dd>
      <dt>Confusion matrix</dt><dd>TP ${ev.true_positives} · FP ${ev.false_positives} · FN ${ev.false_negatives} · TN ${ev.true_negatives}</dd>
      <dt>Precision / recall / F1</dt><dd>${fmt(ev.precision, 3)} / ${fmt(ev.recall, 3)} / ${fmt(ev.f1, 3)}</dd>
      <dt>Missed</dt><dd>${ev.missed.length ? `<span class="status bad">${esc(ev.missed.join(", "))}</span>` : '<span class="status ok">none</span>'}</dd>
      <dt>False alarms</dt><dd>${ev.false_alarms.length ? `<span class="status bad">${esc(ev.false_alarms.join(", "))}</span>` : '<span class="status ok">none</span>'}</dd></dl>`
    : '<p class="muted small-text">No ground truth for this capture. Enter the scanner IPs below (Nmap-tab captures are labelled automatically).</p>';
  $("#labels-form [name=scanners]").value = p.labels?.scanners?.join(", ") || "";

  const cols = ["index", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "tcp_flags", "frame_len", "payload_len"];
  $("#pv-count").textContent = `first ${p.records.length} of ${fmt(st.packets)}`;
  $("#pv-records").innerHTML = `<thead><tr>${cols.map((c) => `<th>${c}</th>`).join("")}</tr></thead><tbody>` +
    p.records.map((r) => `<tr>${cols.map((c) => `<td>${esc(r[c] ?? "")}</td>`).join("")}</tr>`).join("") + "</tbody>";
}

$("#labels-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const scanners = new FormData(e.target).get("scanners").split(/[\s,]+/).filter(Boolean);
  act(e.target.querySelector("button"), async () => { await api("/api/captures/labels", { file: currentCapture, scanners }); preview(currentCapture); });
});

$("#pv-cross").addEventListener("click", (e) => act(e.target, async () => {
  const r = await api("/api/captures/crosscheck", { file: currentCapture });
  $("#cross-card").hidden = false;
  const bad = Object.entries(r.mismatches).filter(([, n]) => n);
  $("#cross").innerHTML = `<dl class="kv"><dt>Packets</dt><dd>built-in ${fmt(r.packets_builtin)} · tshark ${fmt(r.packets_tshark)}</dd>
    <dt>Agreement</dt><dd>${fmt(r.agreement * 100, 3)}% of ${r.fields_compared} fields per packet</dd>
    <dt>Fields that differ</dt><dd>${bad.length ? esc(bad.map(([f, n]) => `${f} (${n})`).join(", ")) : '<span class="status ok">none</span>'}</dd></dl>` +
    (r.examples.length ? `<table class="table mono-table"><thead><tr><th>Frame</th><th>Field</th><th>Built-in</th><th>tshark</th></tr></thead><tbody>${r.examples.map((x) => `<tr><td>${x.frame}</td><td>${esc(x.field)}</td><td>${esc(x.builtin)}</td><td>${esc(x.tshark)}</td></tr>`).join("")}</tbody></table>` : "");
}, "Comparing…"));

// ====================================================================== nmap
$("#nmap-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = { target: fd.get("target"), ports: fd.get("ports"), scan_type: fd.get("scan_type"), timing: +fd.get("timing"),
    service_detection: fd.has("service_detection"), use_nmap: fd.has("use_nmap"), capture_interface: fd.get("capture_interface") };
  act(e.target.querySelector("button[type=submit]"), async () => {
    const r = await api("/api/nmap", body);
    $("#nmap-meta").textContent = `${r.engine} · ${fmt(r.ports_scanned)} ports · ${r.elapsed_s} s`;
    $("#nmap-table tbody").innerHTML = r.open.map((p) => `<tr><td class="num">${p.port}/${esc(p.proto)}</td><td>${esc(p.service || "?")}</td><td class="detail">${esc(p.product || "–")}</td><td class="detail">${esc(p.reason)}</td></tr>`).join("") || '<tr><td colspan="4" class="muted">No open ports.</td></tr>';
    $("#nmap-cmd").textContent = "$ " + r.command;
    $("#nmap-result").innerHTML = `<dl class="kv"><dt>Target</dt><dd>${esc(r.target)} (${esc(r.ip)})</dd><dt>Scanner address</dt><dd>${esc(r.scanner_ip)}</dd>
      <dt>Port states</dt><dd>${esc(Object.entries(r.states).map(([k, v]) => `${k} ${v}`).join(" · "))}</dd>
      <dt>Capture</dt><dd>${r.capture ? `<code>${esc(r.capture)}</code>, labelled with scanner ${esc(r.scanner_ip)}` : "not captured (pick an interface to record the scan)"}</dd></dl>` +
      (r.capture ? `<div class="row-gap" style="margin-top:12px"><button class="primary small" id="nmap-analyse">Analyse capture</button></div>` : "");
    if (r.capture) $("#nmap-analyse").addEventListener("click", () => { showTab("acquire"); preview(r.capture); });
  }, "Scanning…");
});

// ====================================================================== cases
let currentCase = null;
async function loadCases() {
  const [{ cases }, caps] = await Promise.all([api("/api/cases"), api("/api/captures")]);
  fillSelect($("#seal-file"), caps.files.map((f) => f.file));
  $("#case-table tbody").innerHTML = cases.map((c) => `<tr class="click ${c.case_id === currentCase ? "sel" : ""}" data-case="${esc(c.case_id)}">
      <td>${c.derived_from ? '<span class="status bad"></span>' : ""}<b>${esc(c.case_id)}</b><div class="detail">${esc(c.source_file)} · ${esc(c.investigator)}</div></td>
      <td class="num">${fmt(c.records)}</td><td class="num">${fmt(c.alerts)}</td>
      <td>${c.keyed ? '<span class="status ok">yes</span>' : '<span class="muted">no</span>'}</td>
      <td><button class="ghost small" data-del="${esc(c.case_id)}">Delete</button></td></tr>`).join("") || '<tr><td colspan="5" class="muted">No cases yet.</td></tr>';
  $$("#case-table tr[data-case]").forEach((tr) => tr.addEventListener("click", (e) => { if (!e.target.dataset.del) openCase(tr.dataset.case); }));
  $$("#case-table [data-del]").forEach((b) => b.addEventListener("click", () => {
    if (confirm(`Delete case ${b.dataset.del} and its evidence files?`)) act(b, async () => { await api(`/api/cases/${encodeURIComponent(b.dataset.del)}/delete`, {}); if (currentCase === b.dataset.del) { currentCase = null; $("#case-detail").hidden = true; } loadCases(); });
  }));
  fillSelect($("#matrix-case"), cases.filter((c) => !c.derived_from).map((c) => c.case_id));
  if (currentCase && cases.some((c) => c.case_id === currentCase)) $("#matrix-case").value = currentCase.split("~")[0];
  return cases;
}

$("#seal-form").addEventListener("submit", (e) => {
  e.preventDefault();
  if (!needPass()) return;
  const fd = new FormData(e.target);
  act(e.submitter, async () => {
    const r = await api("/api/cases/seal", { file: fd.get("file"), case_id: fd.get("case_id"), investigator: fd.get("investigator"), passphrase: passphrase(),
      kdf_iterations: +fd.get("kdf_iterations"), threshold: +fd.get("threshold"), window: +fd.get("window"), custodian: fd.has("custodian") });
    $("#seal-result").innerHTML = `<div class="loc window" style="border-left-color:var(--good);background:rgba(12,163,12,.08)">Sealed <b>${esc(r.case_id)}</b>: ${fmt(r.records)} packets, ${r.alerts} alerts${r.keyed ? ", NMAC-tagged" : ""}, ${fmt(r.total_ms)} ms<br><span class="detail mono">root ${esc(r.root_hash)}</span></div>`;
    e.target.case_id.value = "";
    await loadCases();
    openCase(r.case_id);
  }, "Sealing…");
});

async function openCase(id) {
  currentCase = id;
  $$("#case-table tr[data-case]").forEach((tr) => tr.classList.toggle("sel", tr.dataset.case === id));
  const d = await api("/api/cases/" + encodeURIComponent(id));
  const r = d.report, ki = r.keyed_integrity;
  $("#case-detail").hidden = false;
  $("#cd-title").innerHTML = `${esc(id)} ${d.derived_from ? `<span class="status bad detail">tampered copy of ${esc(d.derived_from)}</span>` : ""}`;
  $("#cd-files").innerHTML = d.files.map((f) => `<a class="btn" href="/files/cases/${encodeURIComponent(id)}/${encodeURIComponent(f.file)}">${esc(f.file)}</a>`).join("");
  const kv = (pairs) => `<dl class="kv">${pairs.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("")}</dl>`;
  $("#cd-summary").innerHTML = [
    kv([["Investigator", esc(r.case.investigator)], ["Sealed at", esc(r.case.sealed_at)], ["Source", esc(r.acquisition.source_file) + " · " + kib(r.acquisition.source_size)], ["Source SHA-256", `<span class="mono">${short(r.acquisition.source_sha256, 24)}</span>`]]),
    kv([["Records", fmt(r.integrity.record_count)], ["H₀", `<span class="mono">${short(r.integrity.h0, 24)}</span>`], ["Root hash", `<span class="mono">${short(r.integrity.root_hash, 24)}</span>`], ["Checkpoints", `${Object.keys(r.integrity.checkpoints).length} (every ${r.integrity.checkpoint_interval})`]]),
    kv([["Cipher", esc(r.evidence_container.cipher)], ["KDF", `${esc(r.evidence_container.kdf)} · ${fmt(r.evidence_container.kdf_iterations)}`], ["Container", kib(r.evidence_container.size)], ["Container SHA-256", `<span class="mono">${short(r.evidence_container.sha256, 24)}</span>`]]),
    kv([["Signature", `${esc(r.signer.algorithm)} ${d.signature_valid ? '<span class="status ok">valid</span>' : d.signature_valid === false ? '<span class="status bad">INVALID</span>' : ""}`], ["Signer", `<span class="mono">${short(r.signer.public_key_fingerprint, 23)}</span>`],
      ["NMAC tags", ki ? `<span class="status ok">${fmt(ki.tag_count)}</span> custodian <span class="mono">${short(ki.custodian_key_fingerprint, 23)}</span>` : '<span class="muted">not keyed</span>'], ["Scan alerts", fmt(r.detection.alerts.length)]]),
  ].join("");
  $("#verify-out").innerHTML = '<span class="muted">Public checks run without a passphrase; enter it above for all layers.</span>';
  $("#chain-strip").innerHTML = "";
  $("#tamper-out").innerHTML = "";
  $("#query-table").innerHTML = ""; $("#query-meta").textContent = "";
  $("#tamper-form [name=index]").max = r.integrity.record_count;
  $("#case-detail").scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderVerification(v, target) {
  const statusCls = { PASS: "pass", FAIL: "fail", SKIP: "skip" };
  let html = `<div class="verdict ${v.ok ? "ok" : "bad"}">${esc(v.summary)}</div>
    <ul class="checks">${v.checks.map((c) => `<li><span class="st ${statusCls[c.status]}">${c.status}</span><b>${esc(c.name)}</b><span class="d">${esc(c.detail)}</span><span class="t">${c.status === "SKIP" ? "" : fmt(c.ms, 1) + " ms"}</span></li>`).join("")}</ul>`;
  const l = v.localisation;
  if (l) html += l.kind === "exact"
    ? `<div class="loc">Tampering localised to <b>record ${fmt(l.position)}</b> (frame #${fmt(l.frame)}) by ${esc(l.by)}.</div>`
    : `<div class="loc window">Chain was rebuilt; signed checkpoints narrow it to <b>records ${fmt(l.from)}–${fmt(l.to)}</b>. Seal with a custodian key to pinpoint the exact record.</div>`;
  target.innerHTML = html;
  chainStrip($("#chain-strip"), v);
}

function chainStrip(c, v) {
  const n = v.records, ci = v.checkpoint_interval, l = v.localisation;
  const f = svgFrame(c, 58), x0 = 4, x1 = f.width - 4, y = 18, h = 16;
  const sx = (p) => x0 + ((p - 1) / Math.max(n - 1, 1)) * (x1 - x0);
  txt(f.svg, x0, 11, "record 1");
  txt(f.svg, x1, 11, "record " + fmt(n), { "text-anchor": "end" });
  const segs = Math.ceil(n / ci);
  for (let s = 0; s < segs; s++) {
    const from = s * ci + 1, to = Math.min(n, (s + 1) * ci);
    const chainRan = v.checks.some((k) => k.name === "Hash chain" && k.status !== "SKIP");
    let color = chainRan ? css("--good") : css("--axis");
    if (l && l.kind === "window") color = from >= l.from && to <= l.to ? css("--warning") : to < l.from ? css("--good") : css("--axis");
    if (l && l.kind === "exact") color = to < l.position ? css("--good") : from > l.position ? css("--critical") : css("--warning");
    const r = el("rect", { x: sx(from), y, width: Math.max(1, sx(to) - sx(from) - 1), height: h, fill: color, rx: 2 }, f.svg);
    const state = !chainRan ? "not checked (needs the passphrase)" : !l ? "verified"
      : l.kind === "exact" ? (to < l.position ? "verified" : from > l.position ? "invalid: follows the altered record" : "contains the altered record")
      : from >= l.from && to <= l.to ? "checkpoint mismatch: tampering is in here" : to < l.from ? "matches its signed checkpoint" : "after the tampered window";
    r.addEventListener("mousemove", (e) => showTip(e, `<div class="t">records ${fmt(from)}–${fmt(to)}</div>${state}`));
    r.addEventListener("mouseleave", hideTip);
  }
  if (l && l.kind === "exact") {
    const x = sx(l.position);
    el("line", { x1: x, x2: x, y1: y - 4, y2: y + h + 4, stroke: css("--critical"), "stroke-width": 3 }, f.svg);
    txt(f.svg, Math.min(Math.max(x, 60), f.width - 60), 54, `frame #${fmt(l.frame)}`, { "text-anchor": "middle", class: "value" });
  } else if (l) txt(f.svg, (sx(l.from) + sx(l.to)) / 2, 54, `records ${fmt(l.from)}–${fmt(l.to)}`, { "text-anchor": "middle", class: "value" });
  else txt(f.svg, f.width / 2, 54, `${segs} checkpoint windows of ${ci} records`, { "text-anchor": "middle" });
}

async function verify(id, btn) {
  return act(btn, async () => {
    const v = await api(`/api/cases/${encodeURIComponent(id)}/verify`, { passphrase: passphrase() || null, use_custodian: $("#use-custodian").checked });
    
    renderVerification(v, $("#verify-out"));
    return v;
  }, "Verifying…");
}
$("#verify-btn").addEventListener("click", (e) => verify(currentCase, e.target));

$("#tamper-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  if (!["bitflip", "unindex"].includes(fd.get("mode")) && !needPass()) return;
  act(e.submitter, async () => {
    const t = await api(`/api/cases/${encodeURIComponent(currentCase)}/tamper`, { mode: fd.get("mode"), index: +fd.get("index"), field: fd.get("field"), value: fd.get("value"), passphrase: passphrase() });
    await loadCases();
    await openCase(t.case_id);
    $("#tamper-out").innerHTML = `<div class="loc">ATTACK on copy <b>${esc(t.case_id)}</b>: ${esc(t.attack)}</div>`;
    await verify(t.case_id, $("#verify-btn"));
  }, "Attacking…");
});

$("#query-form").addEventListener("submit", (e) => {
  e.preventDefault();
  if (!needPass()) return;
  const body = Object.fromEntries(new FormData(e.target));
  body.passphrase = passphrase();
  act(e.submitter, async () => {
    const r = await api(`/api/cases/${encodeURIComponent(currentCase)}/query`, body);
    $("#query-meta").innerHTML = r.mode === "index"
      ? `<b>Blind index</b>: ${fmt(r.total)} matching packets (showing ${r.rows.length}) · key derivation ${fmt(r.kdf_ms)} ms · token lookup ${fmt(r.query_ms, 2)} ms · decrypted only ${fmt(r.decrypted_records)} records (${fmt(r.decrypt_ms, 2)} ms)` +
        (r.trapdoors.length ? `<div class="detail">What the store saw: ${r.trapdoors.map((t) => `<span class="mono">${esc(t.field)}=${esc(t.token.slice(0, 16))}…</span>`).join(" · ")}</div>`
                            : `<div class="detail">No search terms: the store returned records by position only.</div>`)
      : `<b>Full decryption</b>: ${fmt(r.total)} matching packets (showing ${r.rows.length}) · decrypted all ${fmt(r.decrypted_records)} records + GCM check ${fmt(r.decrypt_ms)} ms · SQL query ${fmt(r.query_ms, 2)} ms`;
    const cols = ["idx", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "tcp_flags", "frame_len", "chain_hash"];
    $("#query-table").innerHTML = `<thead><tr>${cols.map((c) => `<th>${c}</th>`).join("")}</tr></thead><tbody>` +
      r.rows.map((row) => `<tr>${cols.map((c) => `<td>${esc(c === "chain_hash" ? short(row[c], 12) : row[c] ?? "")}</td>`).join("")}</tr>`).join("") + "</tbody>";
  }, "Searching…");
});

// ====================================================================== security
async function loadSecurity() {
  const [s] = await Promise.all([api("/api/security"), loadCases()]);
  let group = "";
  $("#measures tbody").innerHTML = s.measures.map((m) => {
    const head = m.group !== group ? `<tr><td colspan="3" class="muted small-text" style="padding-top:14px">${esc((group = m.group))}</td></tr>` : "";
    return head + `<tr><td><b>${esc(m.name)}</b>${m.technique ? `<div class="detail">${esc(m.technique)}</div>` : ""}</td>
      <td><span class="status ${m.active ? "ok" : "warn"}">${m.active ? "Active" : "Attention"}</span></td><td class="detail">${esc(m.detail)}</td></tr>`;
  }).join("");
}

const ATTACK_NAMES = { modify: "Modify one field", delete: "Delete a packet", insert: "Insert a forged packet", recompute: "Modify + rebuild chain", bitflip: "Flip a ciphertext bit", unindex: "Hide a packet from search",
  report_edit: "Edit the signed report", wrong_passphrase: "Wrong passphrase", swap_signature: "Re-sign with attacker key" };
$("#matrix-form").addEventListener("submit", (e) => {
  e.preventDefault();
  if (!needPass()) return;
  const fd = new FormData(e.target);
  act(e.submitter, async () => {
    const m = await api(`/api/cases/${encodeURIComponent(fd.get("case"))}/matrix`, { passphrase: passphrase(), index: fd.get("index") ? +fd.get("index") : null });
    const cls = { PASS: "pass", FAIL: "fail", SKIP: "skip" };
    const locTxt = (l) => !l ? "–" : l.kind === "exact" ? `record ${fmt(l.position)}` : `records ${fmt(l.from)}–${fmt(l.to)}`;
    $("#matrix-meta").textContent = `${m.case_id} · target frame ${fmt(m.index)} · ${m.rows.filter((r) => r.detected).length}/${m.rows.length} detected`;
    $("#matrix").innerHTML = `<thead><tr><th>Attack</th>${m.layers.map((l) => `<th>${esc(l)}</th>`).join("")}<th>Result</th><th>Chain only</th><th>What the attacker did</th></tr></thead><tbody>` +
      m.rows.map((r) => `<tr><td title="${esc(r.what)}"><b>${esc(ATTACK_NAMES[r.attack] || r.attack)}</b></td>
        ${m.layers.map((l) => `<td><span class="st ${cls[r.checks[l]] || "skip"}">${r.checks[l] || "–"}</span></td>`).join("")}
        <td>${r.detected ? '<span class="status ok">detected</span>' : '<span class="status bad">MISSED</span>'}<div class="detail">${locTxt(r.localised)}</div></td>
        <td class="detail">${locTxt(r.chain_only)}</td><td class="detail">${esc(r.what)}</td></tr>`).join("") + "</tbody>";
    nmacCompare(m);
  }, "Running all attacks…");
});

// ====================================================================== nested MAC
async function computeNmac(e) {
  e?.preventDefault();
  const r = await api("/api/nmac?msg=" + encodeURIComponent($("#nmac-form [name=msg]").value));
  const box = (l, h, c = "") => `<div class="box ${c}"><div class="l">${l}</div><div class="h">${esc(h)}</div></div>`;
  $("#nmac-flow").innerHTML = box("message m", r.message) +
    `<div class="arrow">↓ inner = SHA-256(k1 ‖ m) · key: ${esc(r.key)}</div>` +
    box("inner digest: this is exactly the insecure prefix MAC H(k1 ‖ m), so NMAC never reveals it", r.inner, "bad") +
    '<div class="arrow">↓ tag = SHA-256(k2 ‖ inner): re-keying with k2 hides the extendable state</div>' + box("NMAC tag (what is stored)", r.outer, "out") +
    box("for comparison: HMAC-SHA256, the standardised instance of the same nesting (ipad/opad keys)", r.hmac);
}
$("#nmac-form").addEventListener("submit", computeNmac);

$("#lext-run").addEventListener("click", (e) => act(e.target, async () => {
  const r = await api("/api/nmac/length-extension");
  const row = (n, x) => `<li><span class="st ${x.forgery_accepted ? "fail" : "pass"}">${x.forgery_accepted ? "FORGED" : "SAFE"}</span><b>${n}</b><span class="d">${x.forgery_accepted ? "attacker's tag verifies" : "attacker's tag rejected"}<br><span class="mono">forged ${short(x.forged_tag, 32)}</span></span><span></span></li>`;
  $("#lext-out").innerHTML = `<dl class="kv"><dt>Original</dt><dd class="mono">${esc(r.message)}</dd><dt>Forged</dt><dd class="mono">${esc(r.forged_message_printable)}</dd></dl>
    <ul class="checks">${row("Prefix MAC H(k ‖ m)", r.prefix_mac)}${row("NMAC H(k2 ‖ H(k1 ‖ m))", r.nmac)}</ul>`;
}));

$("#links-run").addEventListener("click", (e) => {
  if (!currentCase) { toast("Open a keyed case in the Cases tab first.", true); return; }
  if (!needPass()) return;
  act(e.target, async () => {
    const r = await api(`/api/cases/${encodeURIComponent(currentCase)}/nmac-chain`, { passphrase: passphrase() });
    $("#links-out").innerHTML = `<p class="small-text">${esc(currentCase)}</p><table class="table mono-table"><thead><tr><th>n</th><th>H<sub>n</sub></th><th>stored T<sub>n</sub></th><th></th></tr></thead><tbody>` +
      r.links.map((l) => `<tr><td>${l.position}</td><td>${short(l.chain_hash, 14)}</td><td>${short(l.stored_tag, 14)}</td><td>${l.stored_tag === l.expected_tag ? '<span class="st pass">OK</span>' : '<span class="st fail">BAD</span>'}</td></tr>`).join("") + "</tbody></table>";
  });
});

function nmacCompare(m) {
  const r = m.rows.find((x) => x.attack === "recompute");
  if (!r) return;
  const keyed = m.layers.includes("NMAC tags");
  const loc = (l) => !l ? "not localised" : l.kind === "exact" ? `exact: record ${fmt(l.position)}` : `window: records ${fmt(l.from)}–${fmt(l.to)} (${fmt(l.to - l.from + 1)} candidates)`;
  $("#nmac-compare").innerHTML = `<dl class="kv"><dt>Case</dt><dd>${esc(m.case_id)} · insider edits frame ${fmt(m.index)} and rebuilds every later chain hash</dd>
    <dt>SHA-256 chain + signed checkpoints</dt><dd><span class="status warn">${loc(r.chain_only)}</span></dd>
    <dt>+ custodian NMAC tags</dt><dd>${keyed ? `<span class="status ok">${loc(r.localised)}</span>` : '<span class="muted">case was sealed without a custodian key</span>'}</dd></dl>`;
}

const NB = [["prefix", "--series-1", "Prefix MAC (insecure)"], ["nmac", "--series-2", "NMAC"], ["hmac", "--series-3", "HMAC-SHA256"]];
legend("#nbench-legend", NB.map(([, c, l]) => [css(c), l]));
$("#nbench-run").addEventListener("click", (e) => act(e.target, async () => {
  const { rows } = await api("/api/nmac/bench");
  groupedBars($("#nbench-chart"), rows.map((r) => ({ label: fmt(r.bytes) + " B", values: r })), NB.map(([k, c, l]) => [k, css(c), l]), " µs");
}, "Running…"));

// ====================================================================== boot
(async () => {
  const o = await api("/api/overview").catch(() => null);
  if (o) { window.LAST_KEYS = o.keys; loadTools(o.tools); }
  const start = location.hash.slice(1);
  showTab($(`.tab[data-tab="${start}"]`) ? start : "overview");
})();
let resizeTimer;
addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => activeTab === "overview" && loadOverview(), 200); });
