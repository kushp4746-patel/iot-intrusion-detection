// Dashboard, history and model info. Uses helpers from script.js ($, NORMAL, PRESETS, apiBase, applyPreset, buildRow, setMsg).
const KEY = "iot_shield_history";
const loadHist = () => { try { return JSON.parse(localStorage.getItem(KEY)) || []; } catch { return []; } };
const saveHist = (h) => { try { localStorage.setItem(KEY, JSON.stringify(h)); } catch {} };
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

// ---- Save every prediction made on the Analyze page ----
window.onResult = (d, row) => {
  const h = loadHist();
  const proto = row.TCP ? "TCP" : row.UDP ? "UDP" : row.ICMP ? "ICMP" : "Other";
  h.push({
    id: (h.length ? h[h.length - 1].id : 0) + 1,
    time: new Date().toISOString(),
    label: d.prediction, attack: d.is_attack, conf: d.confidence,
    info: proto + ", " + row.Rate + " pkt/s, avg " + Math.round(row.AVG) + " B, SYN=" + row.syn_count,
  });
  saveHist(h);
  render();
};

// ---- Drawing helpers ----
function donut(n, a) {
  const t = n + a, pn = t ? (n / t) * 100 : 0;
  const ring = (color, len, off) => '<circle cx="21" cy="21" r="15.9155" fill="none" stroke="' + color + '" stroke-width="5" stroke-dasharray="' + len + " " + (100 - len) + '" stroke-dashoffset="' + off + '"/>';
  return '<svg viewBox="0 0 42 42" class="donut" role="img" aria-label="Normal ' + n + ", attack " + a + '">' +
    ring("var(--line)", 100, 25) + (t ? ring("var(--good)", pn, 25) + ring("var(--bad)", 100 - pn, 25 - pn) : "") + "</svg>" +
    '<div class="legend"><span><i style="background:var(--good)"></i>Normal ' + n + '</span><span><i style="background:var(--bad)"></i>Attack ' + a + "</span></div>";
}
function lines(h) {
  const last = h.slice(-20);
  let n = 0, a = 0;
  const pn = [], pa = [];
  last.forEach((r) => { r.attack ? a++ : n++; pn.push(n); pa.push(a); });
  const max = Math.max(1, n, a), step = last.length > 1 ? 300 / (last.length - 1) : 0;
  const pts = (arr) => arr.map((v, i) => (i * step).toFixed(1) + "," + (104 - (v / max) * 98).toFixed(1)).join(" ");
  const line = (arr, color) => '<polyline points="' + pts(arr) + '" fill="none" stroke="' + color + '" stroke-width="2.5" vector-effect="non-scaling-stroke"/>';
  return '<svg viewBox="0 0 300 110" class="lines" preserveAspectRatio="none" role="img" aria-label="Running totals">' +
    line(pn, "var(--good)") + line(pa, "var(--bad)") + "</svg>" +
    '<div class="legend"><span><i style="background:var(--good)"></i>Normal</span><span><i style="background:var(--bad)"></i>Attack</span></div>';
}
const avgConf = (list) => (list.length ? list.reduce((s, r) => s + r.conf, 0) / list.length : 0);
function confBar(label, list, cls) {
  const p = Math.round(avgConf(list) * 100);
  return '<div class="bar"><div><span>' + label + "</span><span>" + (list.length ? p + "%" : "no data") + '</span></div><div class="track"><div class="fill ' + cls + '" style="width:' + p + '%"></div></div></div>';
}
function rows(list) {
  if (!list.length) return '<tr><td colspan="5" class="empty">No predictions yet. Open Analyze traffic to make one.</td></tr>';
  return list.map((r) => "<tr><td>" + r.id + "</td><td>" + esc(new Date(r.time).toLocaleString()) + "</td><td>" + esc(r.info) +
    '</td><td><span class="badge ' + (r.attack ? "" : "normal") + '">' + esc(r.attack ? r.label : "Normal") + "</span></td><td>" + Math.round(r.conf * 100) + "%</td></tr>").join("");
}

// ---- Draw all views from the saved history ----
function render() {
  const h = loadHist(), att = h.filter((r) => r.attack), nor = h.filter((r) => !r.attack);
  $("sTotal").textContent = h.length;
  $("sNormal").textContent = nor.length;
  $("sAttack").textContent = att.length;
  $("sRate").textContent = (h.length ? Math.round((att.length / h.length) * 100) : 0) + "%";
  $("donut").innerHTML = donut(nor.length, att.length);
  $("lines").innerHTML = lines(h);
  $("conf").innerHTML = confBar("Normal", nor, "normal") + confBar("Attack", att, "");
  $("recent").innerHTML = rows(h.slice(-8).reverse());
  const f = $("filter").value;
  $("all").innerHTML = rows(h.filter((r) => f === "all" || (f === "attack") === r.attack).reverse());
}
$("filter").onchange = render;
$("clear").onclick = () => { if (confirm("Delete all saved predictions?")) { saveHist([]); render(); } };

// ---- Run the six examples through the real model ----
$("runAll").onclick = async () => {
  $("runAll").disabled = true;
  setMsg("Running examples...");
  try {
    for (const p of Object.values(PRESETS)) {
      applyPreset(p);
      const row = buildRow();
      const res = await fetch(apiBase() + "/predict", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(row) });
      if (!res.ok) throw new Error("backend error");
      window.onResult(await res.json(), row);
    }
    setMsg("Added " + Object.keys(PRESETS).length + " predictions. Open the Dashboard to see them.");
  } catch {
    setMsg("Could not finish. Is the backend running at " + apiBase() + "?", true);
  }
  $("runAll").disabled = false;
};

// ---- Model info ----
async function loadModel() {
  try {
    const res = await fetch(apiBase() + "/model-info");
    if (!res.ok) throw new Error();
    const m = await res.json();
    $("modelBox").innerHTML = "<h2>" + esc(m.model) + " classifier</h2>" +
      "<p>Trained on the CICIoT2023 dataset. It reads " + m.num_features + " traffic measurements for each flow and picks one of " + m.classes.length + " classes:</p>" +
      '<div class="chips">' + m.classes.map((c) => "<span>" + esc(c) + "</span>").join("") + "</div>" +
      '<h2>Measurements used</h2><div class="chips">' + m.features.map((c) => "<span>" + esc(c) + "</span>").join("") + "</div>";
  } catch {
    $("modelBox").innerHTML = '<p class="msg err">Cannot reach the backend at ' + esc(apiBase()) + ". Start it and open this page again.</p>";
  }
}

// ---- Switch between views ----
function route() {
  const v = (location.hash || "#dashboard").slice(1);
  const id = ["dashboard", "analyze", "history", "model"].includes(v) ? v : "dashboard";
  document.querySelectorAll("section.view").forEach((s) => s.classList.toggle("hidden", s.id !== id));
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.getAttribute("href") === "#" + id));
  if (id === "model") loadModel();
  render();
}
window.addEventListener("hashchange", route);
route();