/**
 * Prueba del score heurístico F2.1 contra una muestra de URLs (S9)
 * Corre el motor localmente (sin pasar por el endpoint/Lambda), para
 * aislar la cifra de precisión de F2.1 sin que F2.2 se dispare.
 *
 * Uso: node test-muestra.mjs maliciosas.txt limpias.txt [--intervalo 3200] [--salida resultados-f21.csv]
 *
 * Límite de WhoisJSON (20 consultas por minuto):
 *  - Después de cada consulta nueva a la API espera hasta completar --intervalo ms desde que
 *    empezó (3200 ms = unas 18 por minuto). Las respuestas de la caché de DynamoDB no esperan.
 *  - Cada dominio raíz se consulta una sola vez por corrida; las URLs del mismo dominio
 *    reutilizan el resultado.
 *  - Si la API responde 429 tres veces seguidas (cuota mensual o ritmo), detiene la corrida
 *    para no sesgar el resultado con URLs sin WHOIS.
 *
 * Al final imprime cuántas URLs no obtuvieron dato de WHOIS y por qué. El motivo se deduce de
 * los mensajes que whois.mjs escribe con console.error (no hace falta modificar whois.mjs).
 *
 * Calcula:
 * - Precisión: % de maliciosas que el score clasificó como SOSPECHOSO
 * - Tasa de falsos positivos: % de limpias que el score clasificó como SOSPECHOSO
 */
import { readFileSync, writeFileSync } from 'fs';
import { normalizarURL } from '../lambda analisis/normalizarUrl.mjs';
import { calcularScoreHeuristico, extraerDominioRaiz } from '../lambda analisis/heuristica.mjs';
import { obtenerAntiguedadDominio } from '../lambda analisis/whois.mjs';

const args = process.argv.slice(2);
const [archivoMaliciosas, archivoLimpias] = args;
const opcion = (nombre, porDefecto) => {
  const i = args.indexOf(`--${nombre}`);
  return i >= 0 ? args[i + 1] : porDefecto;
};
const INTERVALO_MS = Number(opcion('intervalo', 3200));
const salida = opcion('salida', 'resultados-f21.csv');

if (!archivoMaliciosas || !archivoLimpias) {
  console.error('Uso: node test-muestra.mjs maliciosas.txt limpias.txt [--intervalo 3200] [--salida resultados-f21.csv]');
  process.exit(1);
}

// whois.mjs escribe sus fallos con console.error. Se capturan para clasificar el motivo;
// los avisos propios de este script salen por consolaError.
const consolaError = console.error.bind(console);
let capturados = [];
console.error = (...a) => {
  capturados.push(a.map(String).join(' '));
};

const esperar = (ms) => new Promise((r) => setTimeout(r, ms));

function leerUrls(archivo) {
  return readFileSync(archivo, 'utf-8')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
}

function wilson(x, n, z = 1.96) {
  const p = x / n, z2 = z * z, d = 1 + z2 / n;
  const c = (p + z2 / (2 * n)) / d;
  const m = (z / d) * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n));
  return [Math.max(0, c - m) * 100, Math.min(1, c + m) * 100];
}

function motivoSinDato(errores) {
  const txt = errores.join(' | ');
  if (/HTTP:?\s*429/.test(txt)) return 'limite_429';
  if (/TimeoutError|AbortError|timeout/i.test(txt)) return 'timeout';
  if (/HTTP:?\s*\d{3}/.test(txt)) return 'http_otro';
  if (/Error consultando/.test(txt)) return 'error_red';
  return 'sin_fecha_en_registro'; // dominio no registrado o sin fecha de creación: no es una falla de la consulta
}

const memo = new Map(); // dominio raíz -> resultado de WHOIS en esta corrida
const estado = { consultasApi: 0, aciertosCache: 0, consecutivos429: 0, abortar: false };

async function consultarWhois(dominioRaiz) {
  if (memo.has(dominioRaiz)) return memo.get(dominioRaiz);

  capturados = [];
  const t0 = Date.now();
  const r = await obtenerAntiguedadDominio(dominioRaiz);
  const errores = [...capturados];

  const res = r
    ? { dato: r, motivo: '', origen: r.desdeCache ? 'cache' : 'api' }
    : { dato: null, motivo: motivoSinDato(errores), origen: 'api' };

  if (res.origen === 'cache') {
    estado.aciertosCache++;
  } else {
    estado.consultasApi++;
    const resto = INTERVALO_MS - (Date.now() - t0);
    if (resto > 0) await esperar(resto); // respeta el límite de la API
    if (res.motivo === 'limite_429') {
      estado.consecutivos429++;
      if (estado.consecutivos429 >= 3) estado.abortar = true;
    } else {
      estado.consecutivos429 = 0;
    }
  }
  memo.set(dominioRaiz, res);
  return res;
}

async function analizarUrlLocal(url) {
  try {
    const urlInfo = normalizarURL(url);
    const dominioRaiz = extraerDominioRaiz(urlInfo.dominio);
    const whois = await consultarWhois(dominioRaiz);
    const resultado = calcularScoreHeuristico(urlInfo, whois.dato);
    return { ...resultado, whois };
  } catch (err) {
    consolaError(`Error analizando ${url}:`, err.message);
    return null;
  }
}

async function evaluarMuestra(urls, etiqueta) {
  const resultados = [];
  for (const [i, url] of urls.entries()) {
    if (estado.abortar) break;
    const r = await analizarUrlLocal(url);
    const sospechoso = r?.veredicto === 'SOSPECHOSO';
    const w = r?.whois;
    resultados.push({
      etiqueta,
      url,
      sospechoso,
      score: r?.score ?? null,
      conWhois: Boolean(w?.dato),
      origen: w?.dato ? w.origen : '',
      motivo: w?.dato ? '' : w?.motivo ?? 'error_analisis',
      criterios: (r?.criteriosActivados ?? []).map((c) => c.criterio).join('|'),
    });
    const textoWhois = w?.dato ? (w.origen === 'cache' ? 'caché' : 'API') : `sin dato (${w?.motivo ?? 'error'})`;
    console.log(`[${etiqueta} ${i + 1}/${urls.length}] ${url.slice(0, 80)} → score: ${r?.score ?? 'ERROR'} → ${sospechoso ? 'SOSPECHOSO' : 'no detectado'} | WHOIS: ${textoWhois}`);
  }
  return resultados;
}

function dominiosUnicos(urls) {
  const s = new Set();
  for (const u of urls) {
    try {
      s.add(extraerDominioRaiz(normalizarURL(u).dominio));
    } catch { /* URL inválida: se contará como error al analizarla */ }
  }
  return s;
}

function resumenWhois(titulo, res) {
  const sin = res.filter((x) => !x.conWhois);
  const porMotivo = {};
  for (const x of sin) porMotivo[x.motivo] = (porMotivo[x.motivo] ?? 0) + 1;
  console.log(`${titulo}: ${res.length - sin.length}/${res.length} con dato de WHOIS | sin dato: ${sin.length}`);
  for (const [m, n] of Object.entries(porMotivo)) console.log(`    - ${m}: ${n}`);
}

const maliciosas = leerUrls(archivoMaliciosas);
const limpias = leerUrls(archivoLimpias);

const unicos = new Set([...dominiosUnicos(maliciosas), ...dominiosUnicos(limpias)]);
console.log(`\nURLs: ${maliciosas.length} maliciosas + ${limpias.length} limpias`);
console.log(`Dominios raíz únicos: ${unicos.size} (máximo de consultas a WhoisJSON; la caché de DynamoDB las reduce)`);
console.log(`Intervalo entre consultas nuevas: ${INTERVALO_MS} ms | tiempo máximo estimado: ${Math.ceil((unicos.size * INTERVALO_MS) / 60000)} min`);
console.log('Antes de seguir, confirma que la cuota restante de WhoisJSON sea mayor que ese máximo.');

console.log(`\n=== Evaluando ${maliciosas.length} URLs maliciosas (F2.1 aislado) ===`);
const resultadosMaliciosas = await evaluarMuestra(maliciosas, 'MALICIOSA');

console.log(`\n=== Evaluando ${limpias.length} URLs limpias (F2.1 aislado) ===`);
const resultadosLimpias = estado.abortar ? [] : await evaluarMuestra(limpias, 'LIMPIA');

const todas = [...resultadosMaliciosas, ...resultadosLimpias];

// CSV con el detalle por URL
const celda = (v) => `"${String(v ?? '').replaceAll('"', '""')}"`;
const cab = ['etiqueta', 'url', 'score', 'veredicto', 'con_whois', 'origen_whois', 'motivo_sin_whois', 'criterios'];
writeFileSync(
  salida,
  [
    cab.join(','),
    ...todas.map((x) =>
      [x.etiqueta, x.url, x.score, x.sospechoso ? 'SOSPECHOSO' : 'no detectado', x.conWhois, x.origen, x.motivo, x.criterios].map(celda).join(',')
    ),
  ].join('\n')
);

console.log('\n=== COBERTURA DE WHOIS ===');
resumenWhois('Maliciosas', resultadosMaliciosas);
resumenWhois('Limpias', resultadosLimpias);
resumenWhois('Total', todas);
console.log(`Consultas nuevas a la API: ${estado.consultasApi} | dominios resueltos desde caché de DynamoDB: ${estado.aciertosCache}`);

const sinPorFalla = todas.filter((x) => !x.conWhois && x.motivo !== 'sin_fecha_en_registro');
console.log(`URLs sin WHOIS por falla de la consulta (429, timeout, error HTTP o de red): ${sinPorFalla.length}`);
const enRiesgo = resultadosMaliciosas.filter((x) => !x.conWhois && x.motivo !== 'sin_fecha_en_registro' && !x.sospechoso && x.score > 40).length;
console.log(`Maliciosas no detectadas, sin WHOIS por falla y con puntaje > 40 (pudieron pasar de 60 con +20 de dominio reciente): ${enRiesgo}`);
console.log(`Detalle por URL guardado en ${salida}`);

if (estado.abortar) {
  console.log('\n*** CORRIDA INCOMPLETA: la API respondió 429 tres veces seguidas (cuota mensual agotada o límite de ritmo). ***');
  console.log(`Se evaluaron ${resultadosMaliciosas.length}/${maliciosas.length} maliciosas y ${resultadosLimpias.length}/${limpias.length} limpias. No se calculan las métricas.`);
  process.exitCode = 2;
} else {
  const detectadas = resultadosMaliciosas.filter((r) => r.sospechoso).length;
  const falsosPositivos = resultadosLimpias.filter((r) => r.sospechoso).length;
  const precision = (detectadas / maliciosas.length) * 100;
  const tasaFP = (falsosPositivos / limpias.length) * 100;
  const [pLo, pHi] = wilson(detectadas, maliciosas.length);
  const [fLo, fHi] = wilson(falsosPositivos, limpias.length);

  console.log('\n=== RESULTADOS (F2.1 aislado — sin F2.2) ===');
  console.log(`Precisión heurística: ${precision.toFixed(1)}% (IC 95% Wilson ${pLo.toFixed(1)}-${pHi.toFixed(1)}%) | objetivo: ≥75%`);
  console.log(`Tasa de falsos positivos: ${tasaFP.toFixed(1)}% (IC 95% Wilson ${fLo.toFixed(1)}-${fHi.toFixed(1)}%) | objetivo: ≤10%`);
  console.log(`Maliciosas detectadas: ${detectadas}/${maliciosas.length}`);
  console.log(`Limpias mal clasificadas: ${falsosPositivos}/${limpias.length}`);
}
