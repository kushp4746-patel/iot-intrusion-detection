const $ = (id) => document.getElementById(id);
const NORMAL = ["BENIGN", "BenignTraffic"];
const apiBase = () => $("apiUrl").value.trim().replace(/\/+$/, "");

// [key, label, default value, group]
const FIELDS = [
  ["flow_duration", "Flow duration (seconds)", 0, "g-conn"],
  ["Duration", "Time to live (TTL)", 64, "g-conn"],
  ["Header_Length", "Header length (bytes)", 54, "g-conn"],
  ["Rate", "Packets per second", 5, "g-traffic"],
  ["Min", "Smallest packet (bytes)", 54, "g-traffic"],
  ["AVG", "Average packet (bytes)", 54, "g-traffic"],
  ["Max", "Largest packet (bytes)", 54, "g-traffic"],
  ["Std", "Packet size spread", 0, "g-traffic"],
  ["syn_count", "SYN packets", 0, "g-counts"],
  ["ack_count", "ACK packets", 0, "g-counts"],
  ["fin_count", "FIN packets", 0, "g-counts"],
  ["rst_count", "RST packets", 0, "g-counts"],
  ["urg_count", "URG packets", 0, "g-counts"],
  ["Number", "Packets per window", 9.5, "g-adv"],
  ["Weight", "Weight", 141.55, "g-adv"],
  ["IAT", "Inter-arrival time", 83000000, "g-adv"],
  ["Variance", "Variance", 0, "g-adv"],
  ["Covariance", "Covariance", 0, "g-adv"],
  ["Radius", "Radius", 0, "g-adv"],
];
const FLAGS = [["syn_flag_number", "SYN"], ["ack_flag_number", "ACK"], ["fin_flag_number", "FIN"],
               ["rst_flag_number", "RST"], ["psh_flag_number", "PSH"]];

// Example flows (values taken from real CICIoT2023 rows)
const PRESETS = {
  "Normal web traffic": { protocol: "TCP", app: "HTTPS", flags: ["ack_flag_number"], flow_duration: 34.44, Duration: 200.3, Header_Length: 1316921.1, Rate: 58.8, Min: 54, AVG: 100.63, Max: 340, Std: 75.998, syn_count: 1.4, urg_count: 65.2, rst_count: 1293.9, Number: 13.5, Weight: 244.6, IAT: 166521297.96, Variance: 5830.42, Covariance: 107.69, Radius: 107.69 },
  "SYN flood": { protocol: "TCP", app: "None", flags: ["syn_flag_number"], Header_Length: 54, Rate: 2.56, Min: 54, AVG: 54, Max: 54, syn_count: 1, IAT: 83093394.57 },
  "UDP flood": { protocol: "UDP", app: "None", flags: [], flow_duration: 0.0083, Header_Length: 5213, Rate: 19365.3, Min: 50, AVG: 50, Max: 50, IAT: 83103025.74 },
  "ICMP flood": { protocol: "ICMP", app: "None", flags: [], Header_Length: 0, Rate: 5.5, Min: 42, AVG: 42, Max: 42, IAT: 83132138.13 },
  "Mirai botnet": { protocol: "Other", app: "None", flags: [], Header_Length: 0, Rate: 4.99, Min: 592, AVG: 592, Max: 592, IAT: 83677463.11 },
  "Port scan": { protocol: "TCP", app: "None", flags: ["syn_flag_number"], flow_duration: 0.0024, Duration: 52.3, Header_Length: 68.8, Rate: 122.34, Min: 57.2, AVG: 57.94, Max: 58, Std: 0.209, syn_count: 1, fin_count: 0.2, rst_count: 0.2, Number: 13.5, Weight: 244.6, IAT: 166421613.84, Variance: 0.1596, Covariance: 0.2526, Radius: 0.2526 },
};

// ---- Build the form ----
FIELDS.forEach(([key, label, def, group]) => {
  const l = document.createElement("label");
  l.innerHTML = label + '<input type="number" step="any" id="' + key + '" value="' + def + '">';
  $(group).appendChild(l);
});
FLAGS.forEach(([key, label]) => {
  const l = document.createElement("label");
  l.className = "check";
  l.innerHTML = '<input type="checkbox" id="' + key + '"> ' + label;
  $("flags").appendChild(l);
});

function applyPreset(p) {
  FIELDS.forEach(([key, , def]) => ($(key).value = p[key] ?? def));
  $("protocol").value = p.protocol;
  $("app").value = p.app;
  FLAGS.forEach(([key]) => ($(key).checked = p.flags.includes(key)));
  setMsg("");
}
Object.keys(PRESETS).forEach((name) => {
  const b = document.createElement("button");
  b.className = "ghost";
  b.textContent = name;
  b.onclick = () => applyPreset(PRESETS[name]);
  $("presets").appendChild(b);
});
applyPreset(PRESETS["Normal web traffic"]);

// ---- Turn the form into the 46 values the model expects ----
function buildRow() {
  const row = {};
  FIELDS.forEach(([key]) => (row[key] = parseFloat($(key).value) || 0));
  const p = $("protocol").value, app = $("app").value;
  row["Protocol Type"] = { TCP: 6, UDP: 17, ICMP: 1, Other: 47 }[p];
  ["TCP", "UDP", "ICMP"].forEach((k) => (row[k] = p === k ? 1 : 0));
  ["HTTP", "HTTPS", "DNS"].forEach((k) => (row[k] = app === k ? 1 : 0));
  FLAGS.forEach(([key]) => (row[key] = $(key).checked ? 1 : 0));
  ["Drate", "ece_flag_number", "cwr_flag_number", "Telnet", "SMTP", "SSH", "IRC", "DHCP", "ARP"].forEach((k) => (row[k] = 0));
  row.Srate = row.Rate;
  row.IPv = 1;
  row.LLC = 1;
  row["Tot size"] = row.AVG;
  row["Tot sum"] = row.AVG * (row.Number + 1);
  row.Magnitue = Math.sqrt(2 * row.AVG);
  return row;
}

function setMsg(text, isError = false) {
  $("msg").textContent = text;
  $("msg").classList.toggle("err", isError);
}

// ---- Backend connection ----
async function checkConnection() {
  try {
    const res = await fetch(apiBase() + "/");
    if (!res.ok) throw new Error();
    $("dot").className = "dot on";
    setMsg("Backend connected.");
  } catch {
    $("dot").className = "dot off";
    setMsg("Cannot reach the backend. Start it with: uvicorn main:app --reload", true);
  }
}
$("ping").onclick = checkConnection;
window.addEventListener("load", checkConnection);

// ---- Send to the backend and show the answer ----
$("run").onclick = async () => {
  $("run").disabled = true;
  setMsg("Checking...");
  try {
    const res = await fetch(apiBase() + "/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildRow()),
    });
    const d = await res.json();
    if (!res.ok) throw new Error(typeof d.detail === "string" ? d.detail : "The backend returned an error.");
    show(d);
    setMsg("");
  } catch (err) {
    setMsg(err.message === "Failed to fetch" ? "Cannot reach the backend at " + apiBase() : err.message, true);
  }
  $("run").disabled = false;
};

function show(d) {
  const pct = Math.round(d.confidence * 100);
  const v = $("verdict");
  v.className = "verdict " + (d.is_attack ? "bad" : "good");
  v.innerHTML = d.is_attack
    ? "Attack detected: " + d.prediction + "<small>The model is " + pct + "% sure.</small>"
    : "Looks like normal traffic<small>The model is " + pct + "% sure.</small>";

  $("bars").innerHTML = "";
  d.top.forEach((t) => {
    const normal = NORMAL.includes(t.label);
    const el = document.createElement("div");
    el.className = "bar";
    el.innerHTML = "<div><span></span><span>" + (t.probability * 100).toFixed(1) + "%</span></div>" +
      '<div class="track"><div class="fill ' + (normal ? "normal" : "") + '"></div></div>';
    el.querySelector("span").textContent = normal ? "Normal traffic" : t.label;
    $("bars").appendChild(el);
    setTimeout(() => (el.querySelector(".fill").style.width = t.probability * 100 + "%"), 50);
  });
  $("results").classList.remove("hidden");
  $("results").scrollIntoView({ behavior: "smooth" });
}