import { readFileSync } from 'fs';
import { performance } from 'perf_hooks';
import { normalizarURL } from '../lambda analisis/normalizarUrl.mjs';
import { calcularScoreHeuristico, extraerDominioRaiz } from '../lambda analisis/heuristica.mjs';
import { obtenerAntiguedadDominio } from '../lambda analisis/whois.mjs';

const [, , archivoUrls, archivoDominios] = process.argv;
const leer = (f) => readFileSync(f, 'utf-8').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));

function resumen(valores) {
  const s = [...valores].sort((a, b) => a - b);
  const q = (p) => s[Math.min(s.length - 1, Math.ceil(p * s.length) - 1)];
  return { n: s.length, mediana: q(0.5), p90: q(0.9), max: s[s.length - 1] };
}

// 1) Cómputo de F2.1 (sin WHOIS): solo calcularScoreHeuristico
const tCompute = [];
for (const url of leer(archivoUrls)) {
  const info = normalizarURL(url);
  const t0 = performance.now();
  calcularScoreHeuristico(info, null);
  tCompute.push(performance.now() - t0); // ms
}
console.log('F2.1 cómputo (ms):', resumen(tCompute));

// 2) WHOIS: llamada directa a la API (sin caché), dominios que NO estén en DynamoDB
const tWhois = [];
let nulos = 0;
for (const url of leer(archivoDominios)) {
  const dominio = extraerDominioRaiz(normalizarURL(url).dominio);
  const t0 = performance.now();
  const r = await obtenerAntiguedadDominio(dominio);
  tWhois.push((performance.now() - t0) / 1000); // s
  if (!r) nulos++;
  await new Promise((res) => setTimeout(res, 3500)); // límite de 20 req/min
}
console.log('WHOIS (s):', resumen(tWhois), `| respuestas nulas: ${nulos}`);