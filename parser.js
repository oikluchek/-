// ================================================================
//  cvedcVPN — VPN Config Parser
//  Запуск: node parser.js
//  Переменные окружения:
//    MAX_LIMIT   — максимальное число конфигов (по умолчанию 500)
//    OUTPUT_DIR  — папка для сохранения файлов (по умолчанию ./configs)
// ================================================================

import fs   from 'fs';
import path from 'path';

// ----------------------------------------------------------------
// НАСТРОЙКИ
// ----------------------------------------------------------------

const IS_PUBLIC = true;

const WHITELIST_DOMAINS = [
  'gosuslugi.ru', 'mos.ru', 'nalog.ru', 'zakupki.gov.ru', 'kremlin.ru',
  'government.ru', 'gd.ru', 'genproc.gov.ru', 'mvd.ru', 'mchs.ru',
  'rostrud.gov.ru', 'ach.gov.ru', 'rsv.ru', 'mintrud.gov.ru', 'minfin.gov.ru',
  'council.gov.ru', 'ksrf.ru', 'scrf.gov.ru', 'mid.ru', 'minobrnauki.gov.ru',
  'minzdrav.gov.ru', 'minsport.gov.ru', 'minstroyrf.ru', 'mintrans.gov.ru',
  'minpromtorg.gov.ru', 'digital.gov.ru', 'roskomnadzor.ru',
  'mirpay.ru', 'mironline.ru', 'sbp.nspk.ru',
  'sberbank.ru', 'tbank.ru', 'alfabank.ru', 'vtb.ru', 'psbank.ru',
  'gazprombank.ru', 'open.ru', 'rshb.ru', 'mkb.ru', 'absolutbank.ru',
  'sovcombank.ru', 'bankuralsib.ru', 'raiffeisen.ru', 'citibank.ru',
  'unicreditbank.ru', 'rosbank.ru',
  'beeline.ru', 'megafon.ru', 'mts.ru', 'rt.ru', 't2.ru',
  'sbermobile.ru', 'tmobile.ru', 'ertelecom.ru', 'domru.ru', 'ttk.ru',
  'rostelecom.ru', 'tinkoff.ru', 'yota.ru',
  'vk.com', 'ok.ru', 'mail.ru', 'yandex.ru', 'dzen.ru', 'rutube.ru', 'max.ru',
  'vkvideo.ru', 'sferum.ru', 'disk.yandex.ru', '360.yandex.ru', 'kinopoisk.ru',
  'ivi.ru', 'hh.ru', 'pikabu.ru',
  'ozon.ru', 'wildberries.ru', 'avito.ru', 'megamarket.ru', 'sbermegamarket.ru',
  'magnit.ru', 'vkusvill.ru', 'dixy.ru', 'detmir.ru', 'vkusnoitochka.ru',
  'burgerking.ru', 'kfc.ru', 'cdek.ru', 'samokat.ru', 'kuper.ru', 'gsev.ru',
  'utkonos.ru', 'sbermarket.ru', 'lenta.com', 'perekrestok.ru', '5ka.ru',
  'metro-cc.ru', 'ashan.ru', 'spar.ru', 'petrovich.ru', 'dns-shop.ru', 'drom.ru', 'apteka.ru',
  'rbc.ru', 'gazeta.ru', 'lenta.ru', 'rambler.ru', 'kp.ru', 'ria.ru', 'iz.ru',
  'tass.ru', 'kommersant.ru', 'vedomosti.ru', 'mk.ru', 'rg.ru', 'ntv.ru', '1tv.ru',
  'rt.ru', 'tnt-online.ru', 'ctc.ru', 'matchtv.ru', 'zvezdanews.ru', 'vmeste-rf.tv',
  'aif.ru', 'pnp.ru', 'vesti.ru', 'russia.tv', 'tvzvezda.ru', 'ren.tv', '5-tv.ru',
  'domashniy.ru', 'muz-tv.ru', 'otr-online.ru', 'tvcenter.ru', 'tv3.ru', 'spastv.ru',
  '2gis.ru', 'yandex.ru/maps', 'russianhighways.ru', 'rzd.ru', 'tutu.ru',
  'maxim.taxi', 'gismeteo.ru', 'yandex.ru/pogoda', 'rasp.yandex.ru', 'aeroflot.ru',
  'pobeda.aero', 's7.ru', 'utair.ru', 'grandservis.ru', 'citydrive.ru',
  'obr.ru', 'edu.ru', 'ege.edu.ru', 'school.ru', 'moodle.ru', 'itmo.ru',
  'bmstu.ru', 'spbu.ru', 'msu.ru', 'mipt.ru', 'hse.ru', 'ranepa.ru', 'mgimo.ru',
  'urfu.ru', 'kpfu.ru', 'nntu.ru', 'tpu.ru', 'susu.ru', 'donstu.ru', 'sfedu.ru',
  'job.ru', 'rabota.ru', 'superjob.ru', 'zarplata.ru', 'avitorabota.ru', 'trudvsem.ru',
  'sberid.ru', 'goskey.ru', 'chestnyznak.ru', 'sbis.ru', 'diadoc.ru',
  'pfr.gov.ru', 'fss.ru', 'cmcsmd.ru', 'rnpk.best', 'banki.ru', 'm.gosuslugi.ru',
  'мойбизнес.рф', 'mspbank.ru', 'kaspersky.ru', 'drweb.ru', 'tensor.ru',
  'kontur.ru', 'evotor.ru', 'inspectsme.ru', 'rosagroleasing.ru', 'vseinstrumenti.ru'
];

const ALLOWED_CIDRS = [
  '5.255.255.0/24',   // Яндекс
  '77.88.0.0/18',     // Яндекс
  '87.250.250.0/24',  // Яндекс
  '95.108.0.0/16',    // Mail.Ru
  '217.69.128.0/20',  // Mail.Ru
  '109.120.128.0/17', // VK
  '185.30.164.0/22',  // VK
  '91.200.120.0/24',  // Сбер
  '193.232.96.0/24',  // Сбер
  '92.223.80.0/22',   // Газпром
  '178.248.0.0/21'    // RT
];

const SOURCES = [
  "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
  "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
  "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
  "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
  "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
  "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt",
  "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/light.txt",
  "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/vless.txt",
  "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix.txt",
  "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/vless.txt",
  "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/main/checked/RU_Best/ru_white.txt",
  "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_lite.txt"
];
for (let i = 1; i <= 20; i++) {
  SOURCES.push(`https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/${i}.txt`);
}

// ----------------------------------------------------------------
// ТАБЛИЦЫ ФЛАГОВ
// ----------------------------------------------------------------

const COUNTRY_MAP = {
  '🇺🇸': 'США', '🇬🇧': 'Великобритания', '🇩🇪': 'Германия', '🇫🇷': 'Франция',
  '🇫🇮': 'Финляндия', '🇳🇱': 'Нидерланды', '🇵🇱': 'Польша', '🇰🇿': 'Казахстан',
  '🇷🇺': 'Россия', '🇺🇦': 'Украина', '🇧🇾': 'Беларусь', '🇨🇳': 'Китай',
  '🇯🇵': 'Япония', '🇰🇷': 'Южная Корея', '🇨🇦': 'Канада', '🇦🇺': 'Австралия',
  '🇮🇳': 'Индия', '🇧🇷': 'Бразилия', '🇲🇽': 'Мексика', '🇿🇦': 'ЮАР',
  '🇪🇸': 'Испания', '🇮🇹': 'Италия', '🇹🇷': 'Турция', '🇮🇱': 'Израиль',
  '🇦🇪': 'ОАЭ', '🇸🇬': 'Сингапур', '🇳🇴': 'Норвегия', '🇸🇪': 'Швеция',
  '🇩🇰': 'Дания', '🇨🇭': 'Швейцария', '🇦🇹': 'Австрия', '🇧🇪': 'Бельгия',
  '🇨🇿': 'Чехия', '🇪🇪': 'Эстония', '🇱🇻': 'Латвия', '🇱🇹': 'Литва',
  '🇷🇴': 'Румыния', '🇧🇬': 'Болгария', '🇭🇺': 'Венгрия', '🇬🇷': 'Греция'
};

const URL_FLAG_MAP = {
  '%F0%9F%87%BA%F0%9F%87%B8': '🇺🇸',
  '%F0%9F%87%AC%F0%9F%87%A7': '🇬🇧',
  '%F0%9F%87%A9%F0%9F%87%AA': '🇩🇪',
  '%F0%9F%87%AB%F0%9F%87%B7': '🇫🇷',
  '%F0%9F%87%AB%F0%9F%87%AE': '🇫🇮',
  '%F0%9F%87%B3%F0%9F%87%B1': '🇳🇱',
  '%F0%9F%87%B5%F0%9F%87%B1': '🇵🇱',
  '%F0%9F%87%B0%F0%9F%87%BF': '🇰🇿',
  '%F0%9F%87%B7%F0%9F%87%BA': '🇷🇺',
  '%F0%9F%87%BA%F0%9F%87%A6': '🇺🇦',
  '%F0%9F%87%A7%F0%9F%87%BE': '🇧🇾',
  '%F0%9F%87%A8%F0%9F%87%B3': '🇨🇳',
  '%F0%9F%87%AF%F0%9F%87%B5': '🇯🇵',
  '%F0%9F%87%B0%F0%9F%87%B7': '🇰🇷',
  '%F0%9F%87%A8%F0%9F%87%A6': '🇨🇦',
  '%F0%9F%87%A6%F0%9F%87%BA': '🇦🇺',
  '%F0%9F%87%AE%F0%9F%87%B3': '🇮🇳',
  '%F0%9F%87%A7%F0%9F%87%B7': '🇧🇷',
  '%F0%9F%87%B2%F0%9F%87%BD': '🇲🇽',
  '%F0%9F%87%BF%F0%9F%87%A6': '🇿🇦',
  '%F0%9F%87%AA%F0%9F%87%B8': '🇪🇸',
  '%F0%9F%87%AE%F0%9F%87%B9': '🇮🇹',
  '%F0%9F%87%B9%F0%9F%87%B7': '🇹🇷',
  '%F0%9F%87%AE%F0%9F%87%B1': '🇮🇱',
  '%F0%9F%87%A6%F0%9F%87%AA': '🇦🇪',
  '%F0%9F%87%B8%F0%9F%87%AC': '🇸🇬',
  '%F0%9F%87%B3%F0%9F%87%B4': '🇳🇴',
  '%F0%9F%87%B8%F0%9F%87%AA': '🇸🇪',
  '%F0%9F%87%A9%F0%9F%87%B0': '🇩🇰',
  '%F0%9F%87%A8%F0%9F%87%AD': '🇨🇭',
  '%F0%9F%87%A6%F0%9F%87%B9': '🇦🇹',
  '%F0%9F%87%A7%F0%9F%87%AA': '🇧🇪',
  '%F0%9F%87%A8%F0%9F%87%BF': '🇨🇿',
  '%F0%9F%87%AA%F0%9F%87%AA': '🇪🇪',
  '%F0%9F%87%B1%F0%9F%87%BB': '🇱🇻',
  '%F0%9F%87%B1%F0%9F%87%B9': '🇱🇹',
  '%F0%9F%87%B7%F0%9F%87%B4': '🇷🇴',
  '%F0%9F%87%A7%F0%9F%87%AC': '🇧🇬',
  '%F0%9F%87%AD%F0%9F%87%BA': '🇭🇺',
  '%F0%9F%87%AC%F0%9F%87%B7': '🇬🇷'
};

const TEXT_COUNTRY_MAP = {
  'us': '🇺🇸', 'usa': '🇺🇸', 'united states': '🇺🇸', 'america': '🇺🇸',
  'uk': '🇬🇧', 'gb': '🇬🇧', 'united kingdom': '🇬🇧', 'great britain': '🇬🇧',
  'de': '🇩🇪', 'germany': '🇩🇪', 'deutschland': '🇩🇪',
  'fr': '🇫🇷', 'france': '🇫🇷',
  'fi': '🇫🇮', 'finland': '🇫🇮', 'suomi': '🇫🇮',
  'nl': '🇳🇱', 'netherlands': '🇳🇱', 'holland': '🇳🇱',
  'pl': '🇵🇱', 'poland': '🇵🇱',
  'kz': '🇰🇿', 'kazakhstan': '🇰🇿',
  'ru': '🇷🇺', 'russia': '🇷🇺',
  'ua': '🇺🇦', 'ukraine': '🇺🇦',
  'by': '🇧🇾', 'belarus': '🇧🇾',
  'cn': '🇨🇳', 'china': '🇨🇳',
  'jp': '🇯🇵', 'japan': '🇯🇵',
  'kr': '🇰🇷', 'korea': '🇰🇷', 'south korea': '🇰🇷',
  'ca': '🇨🇦', 'canada': '🇨🇦',
  'au': '🇦🇺', 'australia': '🇦🇺',
  'in': '🇮🇳', 'india': '🇮🇳',
  'br': '🇧🇷', 'brazil': '🇧🇷',
  'mx': '🇲🇽', 'mexico': '🇲🇽',
  'za': '🇿🇦', 'south africa': '🇿🇦',
  'es': '🇪🇸', 'spain': '🇪🇸',
  'it': '🇮🇹', 'italy': '🇮🇹',
  'tr': '🇹🇷', 'turkey': '🇹🇷',
  'il': '🇮🇱', 'israel': '🇮🇱',
  'ae': '🇦🇪', 'uae': '🇦🇪', 'united arab emirates': '🇦🇪',
  'sg': '🇸🇬', 'singapore': '🇸🇬',
  'no': '🇳🇴', 'norway': '🇳🇴',
  'se': '🇸🇪', 'sweden': '🇸🇪',
  'dk': '🇩🇰', 'denmark': '🇩🇰',
  'ch': '🇨🇭', 'switzerland': '🇨🇭',
  'at': '🇦🇹', 'austria': '🇦🇹',
  'be': '🇧🇪', 'belgium': '🇧🇪',
  'cz': '🇨🇿', 'czech': '🇨🇿', 'czech republic': '🇨🇿',
  'ee': '🇪🇪', 'estonia': '🇪🇪',
  'lv': '🇱🇻', 'latvia': '🇱🇻',
  'lt': '🇱🇹', 'lithuania': '🇱🇹',
  'ro': '🇷🇴', 'romania': '🇷🇴',
  'bg': '🇧🇬', 'bulgaria': '🇧🇬',
  'hu': '🇭🇺', 'hungary': '🇭🇺',
  'gr': '🇬🇷', 'greece': '🇬🇷'
};

// ----------------------------------------------------------------
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ----------------------------------------------------------------

function extractFlagAndCountry(text) {
  if (!text) return { flag: '🌐', country: 'Anycast' };
  const str = String(text);

  // 1. URL-encoded флаги
  for (const [encoded, flag] of Object.entries(URL_FLAG_MAP)) {
    if (str.includes(encoded)) {
      return { flag, country: COUNTRY_MAP[flag] || 'Anycast' };
    }
  }

  // 2. Обычные эмодзи флаги
  const emojiRegex = /[\uD83C][\uDDE6-\uDDFF][\uD83C][\uDDE6-\uDDFF]/g;
  const match = emojiRegex.exec(str);
  if (match) {
    const flag = match[0];
    return { flag, country: COUNTRY_MAP[flag] || 'Anycast' };
  }

  // 3. Текстовые метки в скобках [US], (DE), {RU}
  const bracketMatch = str.match(/[\[\(\{]([A-Z]{2})[\]\)\}]/);
  if (bracketMatch) {
    const code = bracketMatch[1].toLowerCase();
    const flag = TEXT_COUNTRY_MAP[code];
    if (flag) return { flag, country: COUNTRY_MAP[flag] || code.toUpperCase() };
  }

  // 4. Названия стран в тексте
  const lowerText = str.toLowerCase();
  for (const [code, flag] of Object.entries(TEXT_COUNTRY_MAP)) {
    if (lowerText.includes(code)) {
      return { flag, country: COUNTRY_MAP[flag] || code.toUpperCase() };
    }
  }

  // 5. Флаг в начале строки
  const flagAtStart = str.match(/^([\uD83C][\uDDE6-\uDDFF][\uD83C][\uDDE6-\uDDFF])/);
  if (flagAtStart) {
    const flag = flagAtStart[1];
    return { flag, country: COUNTRY_MAP[flag] || 'Anycast' };
  }

  return { flag: '🌐', country: 'Anycast' };
}

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
  const lowerSNI = sni.toLowerCase();
  return WHITELIST_DOMAINS.some(d => lowerSNI === d || lowerSNI.endsWith('.' + d));
}

function extractIPFromUrl(urlPart) {
  try {
    let m = urlPart.match(/@([0-9]{1,3}(?:\.[0-9]{1,3}){3}):/);
    if (m) return m[1];
    m = urlPart.match(/([0-9]{1,3}(?:\.[0-9]{1,3}){3}):[0-9]+/);
    if (m) return m[1];
    m = urlPart.match(/\/\/([0-9]{1,3}(?:\.[0-9]{1,3}){3})/);
    if (m) return m[1];
    return null;
  } catch { return null; }
}

function ipInCidr(ip, cidr) {
  if (!ip) return false;
  const [net, bitsStr] = cidr.split('/');
  if (!bitsStr) return false;
  const bits = parseInt(bitsStr, 10);
  const mask = ~((1 << (32 - bits)) - 1) >>> 0;
  const toInt = addr => addr.split('.').reduce((a, o) => (a << 8) + parseInt(o, 10), 0) >>> 0;
  return (toInt(ip) & mask) === (toInt(net) & mask);
}

function isIpAllowed(ip) {
  if (!ip || !ALLOWED_CIDRS.length) return true;
  return ALLOWED_CIDRS.some(cidr => ipInCidr(ip, cidr));
}

function parseConfigLine(line) {
  line = line.trim();
  if (!line) return null;
  let urlPart = '', comment = '';
  const hashIndex = line.indexOf('#');
  if (hashIndex !== -1) {
    urlPart = line.substring(0, hashIndex).trim();
    comment = line.substring(hashIndex + 1).trim();
  } else {
    urlPart = line;
  }
  const protocols = ['vless://', 'vmess://', 'trojan://', 'ss://'];
  if (!protocols.some(p => urlPart.startsWith(p))) return null;

  const { flag, country } = extractFlagAndCountry(comment + ' ' + urlPart);
  const sni = extractSNI(urlPart, comment);
  if (!isWhitelistedSNI(sni)) return null;
  const ip = extractIPFromUrl(urlPart);
  if (ip && !isIpAllowed(ip)) return null;

  const newName = `${flag} ${country} | SNI ${sni} | 🔥 cvedcVPN sub`;
  return { url: urlPart, flag, country, sni, ip, newName };
}

// ----------------------------------------------------------------
// ФАЙЛОВЫЕ ОПЕРАЦИИ (замена DriveApp)
// ----------------------------------------------------------------

const OUTPUT_DIR = process.env.OUTPUT_DIR || './configs';

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function getMaxLimit() {
  // 1. Переменная окружения
  if (process.env.MAX_LIMIT) {
    const v = parseInt(process.env.MAX_LIMIT, 10);
    if (!isNaN(v) && v > 0) return v;
  }
  // 2. Файл configs/max.txt
  const maxFile = path.join(OUTPUT_DIR, 'max.txt');
  if (fs.existsSync(maxFile)) {
    const v = parseInt(fs.readFileSync(maxFile, 'utf8').trim(), 10);
    if (!isNaN(v) && v > 0) return v;
  }
  return 500;
}

function getNextVersion() {
  const vFile = path.join(OUTPUT_DIR, 'version.txt');
  if (fs.existsSync(vFile)) {
    const v = parseInt(fs.readFileSync(vFile, 'utf8').trim(), 10);
    if (!isNaN(v)) return v + 1;
  }
  return 1;
}

function saveFile(filename, content) {
  ensureDir(OUTPUT_DIR);
  fs.writeFileSync(path.join(OUTPUT_DIR, filename), content, 'utf8');
}

function appendLog(version, total, cidrCount, uniqueSNI) {
  ensureDir(OUTPUT_DIR);
  const logFile = path.join(OUTPUT_DIR, 'log.csv');
  const header = 'datetime,version,total_configs,cidr_priority,unique_sni\n';
  if (!fs.existsSync(logFile)) fs.writeFileSync(logFile, header, 'utf8');
  const row = `${new Date().toISOString()},${version},${total},${cidrCount},${uniqueSNI}\n`;
  fs.appendFileSync(logFile, row, 'utf8');
}

// ----------------------------------------------------------------
// СЕТЕВЫЕ ЗАПРОСЫ (замена UrlFetchApp)
// ----------------------------------------------------------------

async function fetchSource(url) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(15_000) });
    if (!res.ok) {
      console.log(`⚠️  HTTP ${res.status}: ${url}`);
      return [];
    }
    const text = await res.text();
    const configs = [];
    for (const line of text.split('\n')) {
      const parsed = parseConfigLine(line);
      if (parsed) configs.push(parsed);
    }
    return configs;
  } catch (e) {
    console.log(`❌ Ошибка загрузки ${url}: ${e.message}`);
    return [];
  }
}

// ----------------------------------------------------------------
// MAIN
// ----------------------------------------------------------------

async function main() {
  const LIMIT = getMaxLimit();
  console.log(`🔥 cvedcVPN sub 🔥 | лимит: ${LIMIT}`);

  const allConfigs = [];
  const urlSet    = new Set();

  for (const url of SOURCES) {
    if (allConfigs.length >= LIMIT) break;
    console.log(`📡 Загрузка: ${url}`);
    const cfgs = await fetchSource(url);
    for (const cfg of cfgs) {
      if (!urlSet.has(cfg.url)) {
        urlSet.add(cfg.url);
        allConfigs.push(cfg);
        if (allConfigs.length >= LIMIT) break;
      }
    }
  }

  const version        = getNextVersion();
  const now            = new Date();
  const cidrCount      = allConfigs.filter(c => c.ip && isIpAllowed(c.ip)).length;
  const uniqueSNI      = new Set(allConfigs.map(c => c.sni)).size;

  const header = [
    `#profile-title: 🔥 cvedcVPN sub 🔥`,
    `#profile-update-interval: 5`,
    `#announce: парсер работает ⚡`,
    ``
  ].join('\n');

  let content = header;
  for (const cfg of allConfigs) {
    content += `${cfg.url}#${cfg.newName}\n`;
  }

  saveFile('configs.txt', content);
  saveFile('version.txt', version.toString());
  appendLog(version, allConfigs.length, cidrCount, uniqueSNI);

  console.log(`✅ Сохранено ${allConfigs.length} конфигов | версия: ${version} | уникальных SNI: ${uniqueSNI}`);
}

main().catch(err => {
  console.error('Фатальная ошибка:', err);
  process.exit(1);
});
