#!/usr/bin/env node
/**
 * Prueba aislada del flujo URLScan.io (sin VirusTotal, WHOIS, RDS ni S3).
 *
 * Uso:
 *   URLSCAN_API_KEY=xxxx node test-urlscan.mjs https://example.com
 *   URLSCAN_API_KEY=xxxx node test-urlscan.mjs https://example.com --deadline=10000
 *   URLSCAN_API_KEY=xxxx node test-urlscan.mjs --uuid=<uuid-existente>
 *
 * Opciones:
 *   --deadline=MS   Presupuesto de polling (default 25000). Ponlo bajo (ej. 8000)
 *                   para simular el timeout y forzar el fallback de screenshot.
 *   --uuid=UUID     Salta el submit y el polling; prueba solo los endpoints de
 *                   screenshot con un scan que ya existe.
 *   --guardar       Guarda el PNG descargado en ./screenshot-<uuid>.png
 *
 * Requiere Node 18+ (fetch nativo).
 */

import { writeFileSync } from 'node:fs';

const API_KEY = process.env.URLSCAN_API_KEY;
if (!API_KEY) {
  console.error('Falta URLSCAN_API_KEY en el entorno.');
  process.exit(1);
}

// ---- args ----
const args = process.argv.slice(2);
const opt = (nombre) => args.find((a) => a.startsWith(`--${nombre}=`))?.split('=')[1];
const url = args.find((a) => !a.startsWith('--'));
const uuidManual = opt('uuid');
const DEADLINE_MS = Number(opt('deadline') ?? 25000);
const GUARDAR = args.includes('--guardar');

if (!url && !uuidManual) {
  console.error('Uso: node test-urlscan.mjs <url> [--deadline=MS] [--guardar]\n     node test-urlscan.mjs --uuid=<uuid> [--guardar]');
  process.exit(1);
}

const POLL_INTERVAL_MS = 5000;
const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47]);
const t0 = Date.now();
const ts = () => `[+${((Date.now() - t0) / 1000).toFixed(1)}s]`;
const log = (...m) => console.log(ts(), ...m);

const esperar = (ms) => new Promise((r) => setTimeout(r, ms));

async function fetchConTimeout(u, opciones = {}, timeoutMs = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(u, { ...opciones, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

// ---- 1. submit ----
async function enviar(urlObjetivo) {
  const resp = await fetchConTimeout('https://urlscan.io/api/v1/scan/', {
    method: 'POST',
    headers: { 'API-Key': API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: urlObjetivo, visibility: 'unlisted' }),
  });
  const cuerpo = await resp.text();
  if (!resp.ok) throw new Error(`Submit falló: HTTP ${resp.status} -> ${cuerpo.slice(0, 300)}`);
  const data = JSON.parse(cuerpo);
  return { uuid: data.uuid, api: data.api, resultado: data.result };
}

// ---- 2. polling (misma lógica que sandbox.mjs) ----
async function poll(uuid, deadline) {
  let intentos = 0;
  while (Date.now() < deadline) {
    const restante = deadline - Date.now();
    await esperar(Math.min(POLL_INTERVAL_MS, restante));
    if (Date.now() >= deadline) break;

    const timeoutFetch = Math.min(8000, deadline - Date.now());
    if (timeoutFetch <= 0) break;

    intentos++;
    let resp;
    try {
      resp = await fetchConTimeout(`https://urlscan.io/api/v1/result/${uuid}/`, {
        headers: { 'API-Key': API_KEY },
      }, timeoutFetch);
    } catch (err) {
      log(`poll #${intentos}: ${err.name} (timeout del fetch individual)`);
      return { estado: 'timeout_fetch', intentos };
    }

    log(`poll #${intentos}: HTTP ${resp.status}`);
    if (resp.status === 200) return { estado: 'ok', intentos, data: await resp.json() };
    if (resp.status === 404) continue;
    if (resp.status === 410) return { estado: 'eliminado', intentos };
    return { estado: `http_${resp.status}`, intentos };
  }
  return { estado: 'sin_respuesta_a_tiempo', intentos };
}

// ---- 3. resumen del resultado ----
function resumir(data) {
  const reqs = data.data?.requests ?? [];
  const errorCarga = reqs.find((r) => r.request?.primaryRequest)?.response?.failed?.errorText;
  const paginaError = reqs.some((r) => r.request?.documentURL?.startsWith('chrome-error://'));
  console.log('\n--- Resultado del scan ---');
  console.log('Dominio:           ', data.page?.domain);
  console.log('Malicioso:         ', data.verdicts?.overall?.malicious);
  console.log('Score:             ', data.verdicts?.overall?.score);
  console.log('Categorías:        ', (data.verdicts?.overall?.categories ?? []).join(', ') || '-');
  console.log('Destino accesible: ', !errorCarga && !paginaError, errorCarga ? `(${errorCarga})` : '');
  console.log('task.screenshotURL:', data.task?.screenshotURL ?? null);
  console.log('Redirecciones:     ', (data.data?.redirects ?? []).length);
}

// ---- 4. prueba de un endpoint de screenshot ----
async function probarScreenshot(etiqueta, urlShot, uuid) {
  console.log(`\n--- ${etiqueta} ---`);
  console.log('GET', urlShot);
  const inicio = Date.now();
  try {
    const resp = await fetchConTimeout(urlShot, { headers: { 'API-Key': API_KEY } }, 6000);
    const ms = Date.now() - inicio;
    const ct = resp.headers.get('content-type');
    if (!resp.ok) {
      const cuerpo = (await resp.text().catch(() => '')).slice(0, 150);
      console.log(`HTTP ${resp.status} en ${ms}ms | content-type: ${ct}`);
      if (cuerpo) console.log('Cuerpo:', cuerpo);
      return false;
    }
    const bytes = Buffer.from(await resp.arrayBuffer());
    const esPng = bytes.subarray(0, 4).equals(PNG_MAGIC);
    console.log(`HTTP ${resp.status} en ${ms}ms | content-type: ${ct} | ${bytes.length} bytes | PNG válido: ${esPng}`);
    if (esPng && GUARDAR) {
      const nombre = `screenshot-${uuid}-${etiqueta.replace(/\W+/g, '_')}.png`;
      writeFileSync(nombre, bytes);
      console.log('Guardado en', nombre);
    }
    return esPng;
  } catch (err) {
    console.log(`Error en ${Date.now() - inicio}ms:`, err.name === 'AbortError' ? 'timeout' : err.message);
    return false;
  }
}

// ---- main ----
(async () => {
  let uuid = uuidManual;
  let screenshotUrlOrigen = null;

  if (!uuid) {
    log(`Enviando ${url} a URLScan...`);
    const sub = await enviar(url);
    uuid = sub.uuid;
    log('Submit OK, uuid =', uuid);
    log('Reporte:', sub.resultado);

    log(`Polling con deadline de ${DEADLINE_MS}ms...`);
    const res = await poll(uuid, Date.now() + DEADLINE_MS);
    log('Estado del polling:', res.estado, `(${res.intentos} intentos)`);

    if (res.estado === 'ok') {
      resumir(res.data);
      screenshotUrlOrigen = res.data.task?.screenshotURL ?? null;
    } else {
      console.log('\n>> El resultado NO llegó: este es el caso donde aplica el fallback por uuid.');
    }
  }

  console.log('\n===== Pruebas de screenshot =====');

  if (screenshotUrlOrigen) {
    await probarScreenshot('A) task.screenshotURL (flujo normal)', screenshotUrlOrigen, uuid);
  }
  await probarScreenshot('B) /api/v1/result/{uuid}/screenshot/ (tu fallback)',
    `https://urlscan.io/api/v1/result/${uuid}/screenshot/`, uuid);
  await probarScreenshot('C) /screenshots/{uuid}.png (ruta documentada)',
    `https://urlscan.io/screenshots/${uuid}.png`, uuid);

  console.log('\nListo. Si B da 404 y C da 200, cambia la URL del fallback en browserIsolation.mjs.');
})().catch((err) => {
  console.error('\nFallo:', err.message);
  process.exit(1);
});
