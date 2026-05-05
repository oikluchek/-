// ================================================================
//  cvedcVPN — Config Checker (DNS + WebSocket)
//  Читает configs/configs.txt, проверяет каждый конфиг:
//    1. Тип транспорта — только WS (type=ws / net=ws)
//    2. DNS-резолвинг хоста
//    3. TCP-доступность host:port (= WS-соединение живо)
//  Результат → configs/selected.txt
//
//  Запуск: node checker.js
//  Переменные окружения:
//    OUTPUT_DIR      — папка с configs.txt (default: ./configs)
//    CONCURRENCY     — параллельных проверок (default: 20)
//    TCP_TIMEOUT_MS  — таймаут TCP в мс (default: 4000)
//    DNS_TIMEOUT_MS  — таймаут DNS в мс (default: 5000)
// ================================================================

import fs            from 'fs';
import path          from 'path';
import net           from 'net';
import dns           from 'dns/promises';

const OUTPUT_DIR     = process.env.OUTPUT_DIR     || './configs';
const CONCURRENCY    = parseInt(process.env.CONCURRENCY    || '20', 10);
const TCP_TIMEOUT_MS = parseInt(process.env.TCP_TIMEOUT_MS || '4000', 10);
const DNS_TIMEOUT_MS = parseInt(process.env.DNS_TIMEOUT_MS || '5000', 10);

// ----------------------------------------------------------------
// ПАРСИНГ URL КОНФИГА
// ----------------------------------------------------------------

/**
 * Парсит строку конфига. Возвращает { host, port, transport } или null.
 * Поддерживает: vless, vmess, trojan, ss
 */
function parseConfig(line) {
  line = line.trim();
  if (!line) return null;

  // Отрезаем комментарий (#...) — он нам не нужен для проверки
  const hashIdx = line.indexOf('#');
  const rawUrl  = hashIdx !== -1 ? line.substring(0, hashIdx).trim() : line;

  // ── vmess: base64-encoded JSON ───────────────────────────────
  if (rawUrl.startsWith('vmess://')) {
    try {
      const b64  = rawUrl.slice(8);
      const json = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
      const host = json.add || json.host;
      const port = parseInt(json.port, 10);
      const net_ = (json.net  || '').toLowerCase();
      const type = (json.type || '').toLowerCase();
      if (!host || !port) return null;
      // transport: net поле у vmess
      return { host, port, transport: net_ || type || 'tcp', raw: line };
    } catch { return null; }
  }

  // ── vless / trojan / ss ──────────────────────────────────────
  try {
    // Заменяем протокол на https чтобы URL API его принял
    const fakeUrl = rawUrl
      .replace(/^vless:\/\//,  'https://')
      .replace(/^trojan:\/\//, 'https://')
      .replace(/^ss:\/\//,     'https://');

    const u = new URL(fakeUrl);
    const host = u.hostname;
    const port = parseInt(u.port, 10) || 443;

    const params    = u.searchParams;
    const transport = (params.get('type') || params.get('net') || 'tcp').toLowerCase();

    if (!host) return null;
    return { host, port, transport, raw: line };
  } catch { return null; }
}

// ----------------------------------------------------------------
// DNS-ПРОВЕРКА
// ----------------------------------------------------------------

const dnsCache = new Map(); // host → true | false

async function checkDNS(host) {
  if (dnsCache.has(host)) return dnsCache.get(host);

  // IP-адрес — DNS не нужен
  if (net.isIP(host)) {
    dnsCache.set(host, true);
    return true;
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DNS_TIMEOUT_MS);
    await dns.resolve(host);         // бросает при неудаче
    clearTimeout(timer);
    dnsCache.set(host, true);
    return true;
  } catch {
    dnsCache.set(host, false);
    return false;
  }
}

// ----------------------------------------------------------------
// TCP-ПРОВЕРКА (= проверка доступности WS-порта)
// ----------------------------------------------------------------

function checkTCP(host, port) {
  return new Promise(resolve => {
    const socket = new net.Socket();
    let done = false;

    const finish = (ok) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(ok);
    };

    socket.setTimeout(TCP_TIMEOUT_MS);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error',   () => finish(false));

    socket.connect(port, host);
  });
}

// ----------------------------------------------------------------
// ПРОВЕРКА ОДНОГО КОНФИГА
// ----------------------------------------------------------------

async function checkConfig(cfg) {
  // Фильтр: только WS-транспорт
  if (cfg.transport !== 'ws' && cfg.transport !== 'websocket') return false;

  // DNS
  const dnsOk = await checkDNS(cfg.host);
  if (!dnsOk) return false;

  // TCP / WS-порт
  const tcpOk = await checkTCP(cfg.host, cfg.port);
  return tcpOk;
}

// ----------------------------------------------------------------
// ПАРАЛЛЕЛЬНЫЙ ПУЛ
// ----------------------------------------------------------------

async function runPool(tasks, concurrency) {
  const results = new Array(tasks.length).fill(false);
  let idx = 0;

  async function worker() {
    while (idx < tasks.length) {
      const i = idx++;
      results[i] = await tasks[i]();
    }
  }

  const workers = Array.from({ length: concurrency }, () => worker());
  await Promise.all(workers);
  return results;
}

// ----------------------------------------------------------------
// MAIN
// ----------------------------------------------------------------

async function main() {
  const inputFile  = path.join(OUTPUT_DIR, 'configs.txt');
  const outputFile = path.join(OUTPUT_DIR, 'selected.txt');

  if (!fs.existsSync(inputFile)) {
    console.error(`❌ Файл не найден: ${inputFile}`);
    process.exit(1);
  }

  const lines = fs.readFileSync(inputFile, 'utf8').split('\n');

  // Отделяем заголовок (строки начинающиеся с #)
  const headerLines = lines.filter(l => l.startsWith('#') || l.trim() === '');
  const configLines = lines.filter(l =>
    l.trim() && !l.startsWith('#') &&
    /^(vless|vmess|trojan|ss):\/\//.test(l.trim())
  );

  console.log(`📂 Загружено конфигов: ${configLines.length}`);
  console.log(`⚙️  Параллельность: ${CONCURRENCY} | TCP timeout: ${TCP_TIMEOUT_MS}ms | DNS timeout: ${DNS_TIMEOUT_MS}ms`);

  // Парсим
  const parsed = configLines.map(parseConfig).filter(Boolean);
  const wsCount = parsed.filter(c => c.transport === 'ws' || c.transport === 'websocket').length;
  console.log(`🔌 WS-транспорт найден: ${wsCount} из ${parsed.length}`);

  if (wsCount === 0) {
    console.log('⚠️  Нет конфигов с type=ws — selected.txt будет пустым');
  }

  // Запускаем проверки
  let checked = 0;
  const tasks = parsed.map(cfg => async () => {
    const ok = await checkConfig(cfg);
    checked++;
    if (checked % 10 === 0 || checked === parsed.length) {
      process.stdout.write(`\r🔍 Проверено: ${checked}/${parsed.length} | ✅ живых WS: ${tasks.filter ? '?' : '?'}   `);
    }
    return ok ? cfg.raw : null;
  });

  const results = await runPool(tasks, CONCURRENCY);
  const alive   = results.filter(Boolean);

  console.log(`\n✅ Живых WS-конфигов: ${alive.length}`);

  // Формируем selected.txt
  const selectedHeader = [
    `#profile-title: 🔥 cvedcVPN selected 🔥`,
    `#profile-update-interval: 5`,
    `#announce: проверено DNS+WS ⚡ живых: ${alive.length}`,
    ``
  ].join('\n');

  const content = selectedHeader + alive.join('\n') + '\n';
  fs.writeFileSync(outputFile, content, 'utf8');

  // Статистика в лог
  appendCheckLog(alive.length, parsed.length, wsCount);

  console.log(`💾 Сохранено → ${outputFile}`);
}

function appendCheckLog(alive, total, wsTotal) {
  const logFile = path.join(OUTPUT_DIR, 'check_log.csv');
  const header  = 'datetime,alive_ws,total_parsed,total_ws\n';
  if (!fs.existsSync(logFile)) fs.writeFileSync(logFile, header, 'utf8');
  fs.appendFileSync(logFile, `${new Date().toISOString()},${alive},${total},${wsTotal}\n`, 'utf8');
}

main().catch(err => {
  console.error('Фатальная ошибка:', err);
  process.exit(1);
});
