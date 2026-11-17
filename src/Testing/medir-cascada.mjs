/**
 * Mide la cascada completa contra el endpoint real.
 * Produce los datos para: latencia de F2.2 y del flujo completo (M5, M9),
 * disponibilidad de la captura (M7), tiempo de descarga de la captura
 * (aproximación de M8), reparto por filtro y fuente (M13) y prueba de caché.
 *
 * Uso:
 *   node medir-cascada.mjs <invoke-url> <urls.txt> [--f22 30] [--cache 10] [--pausa 3000] [--salida resultados-cascada.csv]
 *
 *   --f22 N     se detiene cuando N análisis llegaron a F2.2 sin caché (0 = recorre toda la lista)
 *   --cache K   repite las primeras K URLs que llegaron a F2.2 para medir el caché
 *   --pausa MS  espera entre solicitudes (por defecto 3000)
 *
 * Cada URL se envía con resultadoF1 = "INCIERTO" (F1 no participa).
 * Las respuestas con desde_cache = true no se usan para medir tiempos.
 * Cada URL nueva gasta: 1 consulta WHOIS, 1 scan de URLScan.io y varias llamadas a VirusTotal.
 */
import { readFileSync, writeFileSync } from 'fs';
import { performance } from 'perf_hooks';

const args = process.argv.slice(2);
const invokeUrl = (args[0] ?? '').replace(/\/$/, '');
const archivo = args[1];
const opcion = (nombre, porDefecto) => {
  const i = args.indexOf(`--${nombre}`);
  return i >= 0 ? args[i + 1] : porDefecto;
};
const objetivoF22 = Number(opcion('f22', 0));
const nCache = Number(opcion('cache', 0));
const pausa = Number(opcion('pausa', 3000));
const salida = opcion('salida', 'resultados-cascada.csv');

if (!invokeUrl || !archivo) {
  console.error('Uso: node medir-cascada.mjs <invoke-url> <urls.txt> [--f22 30] [--cache 10] [--pausa 3000] [--salida archivo.csv]');
  process.exit(1);
}

const esperar = (ms) => new Promise((r) => setTimeout(r, ms));
const leerUrls = (f) =>
  readFileSync(f, 'utf-8').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));

function resumen(valores) {
  if (valores.length === 0) return null;
  const s = [...valores].sort((a, b) => a - b);
  const q = (p) => s[Math.min(s.length - 1, Math.ceil(p * s.length) - 1)];
  return { n: s.length, mediana: q(0.5), p90: q(0.9), max: s[s.length - 1] };
}
const fmt = (r, d = 1) =>
  r ? `n=${r.n} | mediana ${r.mediana.toFixed(d)} | p90 ${r.p90.toFixed(d)} | máx ${r.max.toFixed(d)}` : 'sin datos';

function wilson(x, n, z = 1.96) {
  const p = x / n, z2 = z * z, d = 1 + z2 / n;
  const c = (p + z2 / (2 * n)) / d;
  const m = (z / d) * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n));
  return [Math.max(0, c - m) * 100, Math.min(1, c + m) * 100];
}
const pct = (x, n) => (n ? `${((x / n) * 100).toFixed(1)}%` : 'n/a');

async function analizar(url) {
  const t0 = performance.now();
  try {
    const res = await fetch(`${invokeUrl}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, resultadoF1: 'INCIERTO' }),
      signal: AbortSignal.timeout(100000),
    });
    const data = await res.json().catch(() => null);
    return { status: res.status, segundos: (performance.now() - t0) / 1000, data };
  } catch (err) {
    return { status: 0, segundos: (performance.now() - t0) / 1000, data: null, error: err.name };
  }
}

// Etapa en la que terminó el análisis, según la respuesta
function clasificar(r) {
  const d = r.data;
  if (r.status !== 200 || !d) return 'ERROR';
  if (d.desde_cache) return 'CACHE';
  if (d.filtro_decisivo === 'F1') return 'F1';
  if (d.filtro_decisivo === 'F2.1') return 'F2.1';
  return 'F2.2'; // decidió F2.2 o quedó PENDIENTE después de F2.2
}

// Indicadores que deciden el veredicto SOSPECHOSO en F2.2
function fuentes(d) {
  const ind = (d?.indicadores_f2_2 ?? []).map((i) => i.indicador);
  return {
    urlscan: ['urlscan_verdict_malicioso', 'urlscan_scan_eliminado', 'urlscan_motores_maliciosos',
              'descarga_automatica_detectada', 'categorias_riesgo'].some((i) => ind.includes(i)),
    vt: ind.includes('virustotal_motores_maliciosos'),
  };
}

// Aproximación de M8: descarga de la captura desde este equipo (no es la medición en la app)
async function descargarCaptura(url) {
  const t0 = performance.now();
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(100000) });
    if (!res.ok) return null;
    await res.arrayBuffer();
    return (performance.now() - t0) / 1000;
  } catch {
    return null;
  }
}

const urls = leerUrls(archivo);
const filas = [];
let llegaronF22 = 0;

console.log(`\n=== ${urls.length} URLs en la lista${objetivoF22 ? ` | objetivo: ${objetivoF22} análisis que lleguen a F2.2` : ''} ===\n`);

for (const [i, url] of urls.entries()) {
  if (objetivoF22 && llegaronF22 >= objetivoF22) break;
  const r = await analizar(url);
  const etapa = clasificar(r);
  if (etapa === 'ERROR') {
    console.log(r)
  }
  const f = fuentes(r.data);
  const captura = Boolean(r.data?.screenshot_url);
  const descargaSeg = etapa === 'F2.2' && captura ? await descargarCaptura(r.data.screenshot_url) : null;
  if (etapa === 'F2.2') llegaronF22++;
  filas.push({
    url,
    status: r.status,
    etapa,
    veredicto: r.data?.veredicto_final ?? '',
    filtro: r.data?.filtro_decisivo ?? '',
    segundos: r.segundos,
    captura,
    descargaSeg,
    urlscan: f.urlscan,
    vt: f.vt,
    indicadores: (r.data?.indicadores_f2_2 ?? []).map((x) => x.indicador).join('|'),
  });
  console.log(
    `[${i + 1}/${urls.length}] ${etapa.padEnd(5)} ${(r.data?.veredicto_final ?? 'ERROR').padEnd(10)} ${r.segundos.toFixed(1).padStart(5)} s | captura: ${captura ? 'sí' : 'no'} | ${url.slice(0, 70)}`
  );
  await esperar(pausa);
}

const f22 = filas.filter((x) => x.etapa === 'F2.2');
const conteo = (e) => filas.filter((x) => x.etapa === e).length;

console.log('\n=== REPARTO POR ETAPA (M13) ===');
console.log(`Procesadas: ${filas.length} | resueltas en F1: ${conteo('F1')} | resueltas en F2.1: ${conteo('F2.1')} | llegaron a F2.2: ${f22.length}`);
console.log(`Excluidas: desde caché ${conteo('CACHE')} | errores o tiempo agotado ${conteo('ERROR')}`);
const sosp = f22.filter((x) => x.veredicto === 'SOSPECHOSO' || x.veredicto === 'MALICIOSO');
console.log(`De las que llegaron a F2.2: SOSPECHOSO ${sosp.length} | PENDIENTE ${f22.length - sosp.length}`);
console.log(
  `Fuente de la detección en F2.2: solo VirusTotal ${sosp.filter((x) => x.vt && !x.urlscan).length} | solo URLScan.io ${sosp.filter((x) => x.urlscan && !x.vt).length} | ambas ${sosp.filter((x) => x.urlscan && x.vt).length}`
);

console.log('\n=== LATENCIA OBSERVADA POR EL CLIENTE (s), solo análisis que llegaron a F2.2 ===');
console.log('Todas (aprox. de M5):', fmt(resumen(f22.map((x) => x.segundos))));
console.log('Primeras 20 (M9):    ', fmt(resumen(f22.slice(0, 20).map((x) => x.segundos))));
console.log(`Respuestas de más de 30 s: ${f22.filter((x) => x.segundos > 30).length}`);

console.log('\n=== CAPTURA (M7 y aproximación de M8) ===');
if (f22.length > 0) {
  const conCaptura = f22.filter((x) => x.captura).length;
  const [lo, hi] = wilson(conCaptura, f22.length);
  console.log(`Captura disponible: ${conCaptura}/${f22.length} (${pct(conCaptura, f22.length)}; IC 95% Wilson ${lo.toFixed(1)}-${hi.toFixed(1)}%) | meta >= 80%`);
  console.log('Descarga de la captura (s) desde este equipo:', fmt(resumen(f22.filter((x) => x.descargaSeg != null).map((x) => x.descargaSeg)), 2));
} else {
  console.log('Ningún análisis llegó a F2.2.');
}

const porIndicador = {};
for (const f of filas) {
  for (const ind of f.indicadores.split('|').filter(Boolean)) porIndicador[ind] = (porIndicador[ind] ?? 0) + 1;
}
console.log('\n=== INDICADORES DE ESTA CORRIDA ===');
console.log(porIndicador);

if (nCache > 0) {
  const base = f22.slice(0, nCache);
  console.log(`\n=== SEGUNDA PASADA (CACHÉ) SOBRE ${base.length} URLs ===`);
  const t2 = [];
  let aciertos = 0;
  for (const x of base) {
    const r = await analizar(x.url);
    const hit = r.data?.desde_cache === true;
    if (hit) aciertos++;
    t2.push(r.segundos);
    console.log(`desde_cache=${hit} ${r.segundos.toFixed(2)} s | ${x.url.slice(0, 70)}`);
    await esperar(300);
  }
  console.log(`Respuestas con desde_cache=true: ${aciertos}/${base.length}`);
  console.log('Primera consulta (s):', fmt(resumen(base.map((x) => x.segundos)), 2));
  console.log('Segunda consulta (s):', fmt(resumen(t2), 2));
}

const celda = (v) => `"${String(v ?? '').replaceAll('"', '""')}"`;
const cab = ['url', 'status', 'etapa', 'veredicto', 'filtro', 'segundos', 'captura', 'descarga_seg', 'urlscan', 'vt', 'indicadores'];
const csv = [
  cab.join(','),
  ...filas.map((f) =>
    [f.url, f.status, f.etapa, f.veredicto, f.filtro, f.segundos.toFixed(2), f.captura, f.descargaSeg?.toFixed(2) ?? '', f.urlscan, f.vt, f.indicadores]
      .map(celda)
      .join(',')
  ),
].join('\n');
writeFileSync(salida, csv);
console.log(`\nDetalle por URL guardado en ${salida}`);
