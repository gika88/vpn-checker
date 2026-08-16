"use strict";

const $ = (id) => document.getElementById(id);
const HISTORY_KEY = "vpn-checker-history-v1";
let current = null;

const setBadge = (id, text, kind = "neutral") => {
  const el = $(id); el.textContent = text; el.className = `badge ${kind}`;
};
const safe = (value, fallback = "Unavailable") => value || fallback;

async function fetchJson(url, timeout = 7000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, { signal: controller.signal, cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } finally { clearTimeout(timer); }
}

async function getIPv4AndLocation() {
  const ip = (await fetchJson("https://api.ipify.org?format=json")).ip;
  if (!ip) throw new Error("IPv4 service returned no address");
  const geo = await fetchJson(`https://ipwho.is/${encodeURIComponent(ip)}`);
  if (geo.success === false) throw new Error(geo.message || "Location lookup failed");
  return { ip, geo };
}

async function getIPv6() {
  try {
    const data = await fetchJson("https://api6.ipify.org?format=json", 5000);
    return data.ip && data.ip.includes(":") ? data.ip : null;
  } catch { return null; }
}

function candidateIPs(text) {
  const matches = text.match(/(?:\d{1,3}\.){3}\d{1,3}|(?:[a-f\d]{0,4}:){2,7}[a-f\d]{0,4}/gi) || [];
  return [...new Set(matches.filter((ip) => ip && ip !== "0.0.0.0"))];
}

async function getWebRTCIPs() {
  if (!window.RTCPeerConnection) return { ips: [], unsupported: true };
  const pc = new RTCPeerConnection({ iceServers: [] });
  const found = new Set();
  pc.createDataChannel("check");
  pc.onicecandidate = (event) => event.candidate && candidateIPs(event.candidate.candidate).forEach((ip) => found.add(ip));
  try {
    await pc.setLocalDescription(await pc.createOffer());
    await new Promise((resolve) => { const end = setTimeout(resolve, 2500); pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === "complete") { clearTimeout(end); resolve(); } }; });
    candidateIPs(pc.localDescription?.sdp || "").forEach((ip) => found.add(ip));
  } finally { pc.close(); }
  return { ips: [...found], unsupported: false };
}

function isPublic(ip) {
  if (ip.includes(":")) return !/^(::1|fe80:|fc|fd)/i.test(ip);
  const p = ip.split(".").map(Number);
  return !(p[0] === 10 || p[0] === 127 || p[0] === 0 || (p[0] === 192 && p[1] === 168) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 169 && p[1] === 254));
}

function calculateStatus(data) {
  const publicRtc = data.webrtc.ips.filter(isPublic);
  const unexpectedRtc = publicRtc.filter((ip) => ip !== data.ipv4 && ip !== data.ipv6);
  if (unexpectedRtc.length) return { status: "POSSIBLE LEAK", reason: "WebRTC exposed a public address different from the observed public IP.", css: "leak" };
  if (!data.ipv4) return { status: "WARNING", reason: "The public IPv4 check could not be completed.", css: "warning" };
  return { status: "OK", reason: "No conflicting public address was observed. This is not a guarantee of VPN security.", css: "ok" };
}

function render(data) {
  $("ipv4").textContent = safe(data.ipv4); $("ipv4").classList.remove("skeleton");
  $("ipv6").textContent = data.ipv6 || "No public IPv6 observed";
  setBadge("ipBadge", data.ipv4 ? "DETECTED" : "FAILED", data.ipv4 ? "" : "danger");
  const g = data.geo || {};
  $("country").textContent = [g.flag?.emoji, g.country].filter(Boolean).join(" ") || "Unavailable";
  $("city").textContent = safe(g.city); $("region").textContent = safe(g.region);
  $("isp").textContent = safe(g.connection?.isp); $("asn").textContent = g.connection?.asn ? `AS${g.connection.asn}` : "Unavailable";
  const publicRtc = data.webrtc.ips.filter(isPublic);
  if (data.webrtc.unsupported) { $("webrtcIps").textContent = "WebRTC is not supported by this browser."; setBadge("webrtcBadge", "CANNOT VERIFY", "unknown"); }
  else if (!data.webrtc.ips.length) { $("webrtcIps").textContent = "No numeric ICE candidate IPs visible (they may be hidden by mDNS)."; setBadge("webrtcBadge", "NONE VISIBLE", "neutral"); }
  else { $("webrtcIps").textContent = data.webrtc.ips.join(" · "); setBadge("webrtcBadge", publicRtc.some((ip) => ip !== data.ipv4 && ip !== data.ipv6) ? "REVIEW" : "OBSERVED", publicRtc.some((ip) => ip !== data.ipv4 && ip !== data.ipv6) ? "danger" : ""); }
  if (data.ipv6) { $("ipv6Risk").textContent = "Public IPv6 is reachable. Without knowing the VPN's expected IPv6 exit, leak status cannot be verified."; setBadge("ipv6Badge", "CANNOT VERIFY", "unknown"); }
  else { $("ipv6Risk").textContent = "No public IPv6 was observed by the IPv6-only endpoint. This reduces the visible signal but does not prove IPv6 is disabled everywhere."; setBadge("ipv6Badge", "NOT OBSERVED", "neutral"); }
  const verdict = calculateStatus(data); data.verdict = verdict.status;
  $("overallStatus").textContent = verdict.status; $("statusReason").textContent = verdict.reason; $("statusDot").className = `status-dot ${verdict.css}`;
}

function saveHistory(data) {
  const history = readHistory();
  history.unshift({ id: Date.now(), name: $("testName").value.trim() || "Unnamed check", time: new Date().toISOString(), ipv4: data.ipv4, country: data.geo?.country || "Unknown", status: data.verdict });
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, 10))); renderHistory();
}
function readHistory() { try { const value = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); return Array.isArray(value) ? value : []; } catch { return []; } }
function renderHistory() {
  const history = readHistory();
  $("history").innerHTML = history.length ? history.map((item) => `<div class="history-item"><strong>${escapeHtml(item.name)}</strong><span>${escapeHtml(item.ipv4 || "No IPv4")} · ${escapeHtml(item.country)}</span><span>${new Date(item.time).toLocaleString()}</span><span class="history-status ${item.status.toLowerCase().replaceAll(" ", "-")}">${escapeHtml(item.status)}</span></div>`).join("") : '<p class="empty">No saved checks yet.</p>';
}
function escapeHtml(value) { const div = document.createElement("div"); div.textContent = String(value); return div.innerHTML; }

async function runCheck() {
  const button = $("refreshButton"); button.disabled = true; button.textContent = "CHECKING…"; $("errorBanner").hidden = true;
  $("overallStatus").textContent = "CHECKING…"; $("statusDot").className = "status-dot loading";
  const [ipResult, ipv6, webrtc] = await Promise.all([getIPv4AndLocation().catch((error) => ({ error })), getIPv6(), getWebRTCIPs().catch(() => ({ ips: [], unsupported: true }))]);
  current = { ipv4: ipResult.ip || null, geo: ipResult.geo || null, ipv6, webrtc, checkedAt: new Date().toISOString() };
  if (ipResult.error) { $("errorBanner").textContent = `Public IP lookup failed: ${ipResult.error.message}. You can refresh to try again.`; $("errorBanner").hidden = false; }
  render(current); saveHistory(current); button.disabled = false; button.innerHTML = "↻ &nbsp; REFRESH VPN CHECK";
}

function haversine(a, b) { const rad = (n) => n * Math.PI / 180, R = 6371, dLat = rad(b.latitude-a.latitude), dLon = rad(b.longitude-a.longitude); const x = Math.sin(dLat/2)**2 + Math.cos(rad(a.latitude))*Math.cos(rad(b.latitude))*Math.sin(dLon/2)**2; return 2*R*Math.asin(Math.sqrt(x)); }
function requestLocation() {
  if (!navigator.geolocation) { setBadge("geoBadge", "UNAVAILABLE", "unknown"); $("browserLocation").textContent = "Geolocation is not supported."; return; }
  $("locationButton").disabled = true; setBadge("geoBadge", "REQUESTING", "neutral");
  navigator.geolocation.getCurrentPosition((position) => {
    const browser = { latitude: position.coords.latitude, longitude: position.coords.longitude };
    $("browserLocation").textContent = `${browser.latitude.toFixed(4)}, ${browser.longitude.toFixed(4)} (accuracy ±${Math.round(position.coords.accuracy)} m)`; setBadge("geoBadge", "ALLOWED", "");
    if (current?.geo?.latitude != null) { const km = haversine(browser, current.geo); $("locationComparison").textContent = `Approximate distance from IP location: ${Math.round(km).toLocaleString()} km. A large distance can be expected with a VPN, but is not proof of one.`; }
    else $("locationComparison").textContent = "IP location is unavailable, so the locations cannot be compared.";
    $("locationButton").disabled = false;
  }, (error) => { setBadge("geoBadge", error.code === 1 ? "DENIED" : "UNAVAILABLE", "unknown"); $("browserLocation").textContent = error.code === 1 ? "Location permission was denied. No coordinates were collected." : "The browser could not determine your location."; $("locationButton").disabled = false; }, { enableHighAccuracy: false, timeout: 10000, maximumAge: 60000 });
}

$("refreshButton").addEventListener("click", runCheck);
$("locationButton").addEventListener("click", requestLocation);
$("clearHistory").addEventListener("click", () => { localStorage.removeItem(HISTORY_KEY); renderHistory(); });
renderHistory(); runCheck();
