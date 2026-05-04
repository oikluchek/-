import fetch from "node-fetch";
import fs from "fs";

// ================= CONFIG =================
const IS_PUBLIC = true;
const LIMIT = 500;
const OUTPUT_FILE = "configs.txt";

// ================= ДАННЫЕ =================
const WHITELIST_DOMAINS = [
  'gosuslugi.ru','mos.ru','nalog.ru','zakupki.gov.ru','kremlin.ru'
  // ← вставь полный список как у тебя
];

const ALLOWED_CIDRS = [
  '5.255.255.0/24',
  '77.88.0.0/18'
];

// ================= SOURCES =================
const SOURCES = [
  "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt"
];

for (let i = 1; i <= 20; i++) {
  SOURCES.push(`https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/${i}.txt`);
}

// ================= ЛОГИКА =================

function extractSNI(urlPart, comment) {
  const full = urlPart + '#' + comment;
  let sni = '';
  const sniMatch = full.match(/[?&]sni=([^&]+)/);
  if (sniMatch) sni = decodeURIComponent(sniMatch[1]);

  if (!sni && comment) {
    const hostMatch = comment.match(/host[=:]\s*([^\s,]+)/i);
    if (hostMatch) sni = hostMatch[1];
  }

  return sni || 'sni отсутствует';
}

function isWhitelistedSNI(sni) {
  if (!sni || sni === 'sni отсутствует') return false;
  const lower = sni.toLowerCase();
  return WHITELIST_DOMAINS.some(d => lower === d || lower.endsWith("." + d));
}

function extractIPFromUrl(url) {
  let m = url.match(/@([0-9.]+):/);
  if (m) return m[1];

  m = url.match(/([0-9.]+):\d+/);
  if (m) return m[1];

  return null;
}

function ipToInt(ip) {
  return ip.split('.').reduce((a, b) => (a << 8) + +b, 0) >>> 0;
}

function ipInCidr(ip, cidr) {
  const [net, bits] = cidr.split('/');
  const mask = ~((1 << (32 - bits)) - 1) >>> 0;
  return (ipToInt(ip) & mask) === (ipToInt(net) & mask);
}

function isIpAllowed(ip) {
  if (!ip) return true;
  return ALLOWED_CIDRS.some(c => ipInCidr(ip, c));
}

function parseConfigLine(line) {
  line = line.trim();
  if (!line) return null;

  let urlPart = '', comment = '';
  const i = line.indexOf('#');

  if (i !== -1) {
    urlPart = line.slice(0, i).trim();
    comment = line.slice(i + 1).trim();
  } else {
    urlPart = line;
  }

  if (!/^(vless|vmess|trojan|ss):\/\//.test(urlPart)) return null;

  const sni = extractSNI(urlPart, comment);
  if (!isWhitelistedSNI(sni)) return null;

  const ip = extractIPFromUrl(urlPart);
  if (ip && !isIpAllowed(ip)) return null;

  return `${urlPart}#SNI ${sni}`;
}

async function fetchSource(url) {
  try {
    const res = await fetch(url);
    if (!res.ok) return [];

    const text = await res.text();
    return text.split('\n');
  } catch {
    return [];
  }
}

// ================= MAIN =================

async function main() {
  let results = [];
  let seen = new Set();

  console.log("🔥 parser start");

  for (const url of SOURCES) {
    if (results.length >= LIMIT) break;

    console.log("fetch:", url);

    const lines = await fetchSource(url);

    for (const line of lines) {
      const parsed = parseConfigLine(line);
      if (!parsed) continue;

      if (!seen.has(parsed)) {
        seen.add(parsed);
        results.push(parsed);
      }

      if (results.length >= LIMIT) break;
    }
  }

  const header = [
    "#profile-title: 🔥 cvedcVPN sub 🔥",
    "#profile-update-interval: 5",
    "#announce: github parser ⚡",
    ""
  ].join('\n');

  fs.writeFileSync(OUTPUT_FILE, header + results.join('\n'));

  console.log(`✅ готово: ${results.length}`);
}

main();
