/**
 * Mide la "tasa de detección adicional" de F2.2, separando la señal por
 * fuente (URLScan.io vs VirusTotal), dado que VirusTotal también es una
 * de las fuentes de F1 (Majo) — así que su contribución en F2.2 puede
 * solaparse conceptualmente con F1, mientras que URLScan.io (análisis
 * dinámico) no.
 *
 * NOTA METODOLÓGICA: esta corrida sigue forzando resultadoF1: 'INCIERTO'
 * para todas las URLs (F1 real de Majo aún no integrado end-to-end). Por
 * tanto NO mide exactamente "detección adicional sobre F1 real" como
 * define el protocolo — la corrida oficial de esa métrica queda pendiente
 * hasta integrar el F1 real de Majo. Esta corrida sirve para separar,
 * de forma conservadora, qué parte de la detección de F2.2 viene de una
 * fuente genuinamente distinta (URLScan) vs. una que se solapa con F1
 * (VirusTotal).
 *
 * Uso: node test-f22-deteccion-adicional.mjs <invoke-url> maliciosas-final.txt
 */
import { readFileSync } from 'fs';

const [, , invokeUrl, archivo] = process.argv;
if (!invokeUrl || !archivo) {
  console.error('Uso: node test-f22-deteccion-adicional.mjs <invoke-url> maliciosas.txt');
  process.exit(1);
}

function leerUrls(archivo) {
  return readFileSync(archivo, 'utf-8')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
}

async function analizarUrl(url) {
  try {
    const res = await fetch(`${invokeUrl}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, resultadoF1: 'INCIERTO' }),
    });
    return await res.json();
  } catch (err) {
    console.error(`Error analizando ${url}:`, err.message);
    return null;
  }
}

const urls = leerUrls(archivo);
const resultados = [];

console.log(`\n=== Corriendo ${urls.length} URLs contra el endpoint real ===`);
console.log('(cada una puede tardar hasta ~30s si escala a F2.2 — sé paciente)\n');

for (const [i, url] of urls.entries()) {
  const data = await analizarUrl(url);

  const indicadores = data?.indicadores_f2_2 ?? [];
  const fuentes = indicadores.map((ind) => ind.indicador);
  const tieneUrlscan = fuentes.some((f) => f.startsWith('urlscan_'));
  const tieneVT = fuentes.some((f) => f.startsWith('virustotal_'));

  resultados.push({
    url,
    filtro: data?.filtro_decisivo ?? 'ERROR',
    veredicto: data?.veredicto_final ?? 'ERROR',
    tieneUrlscan,
    tieneVT,
  });

  console.log(`[${i + 1}/${urls.length}] ${url} → ${data?.veredicto_final ?? 'ERROR'} (${data?.filtro_decisivo}) [urlscan:${tieneUrlscan} vt:${tieneVT}]`);
  await new Promise((r) => setTimeout(r, 2000));
}

const resueltasF21 = resultados.filter((r) => r.filtro === 'F2.1').length;
const resueltasF22 = resultados.filter((r) => r.filtro === 'F2.2').length;
const pendientes = resultados.filter((r) => r.veredicto === 'PENDIENTE').length;
const errores = resultados.filter((r) => r.filtro === 'ERROR').length;

const soloUrlscan = resultados.filter((r) => r.tieneUrlscan && !r.tieneVT).length;
const soloVT = resultados.filter((r) => !r.tieneUrlscan && r.tieneVT).length;
const ambas = resultados.filter((r) => r.tieneUrlscan && r.tieneVT).length;

console.log('\n=== RESULTADOS ===');
console.log(`Total muestra: ${urls.length}`);
console.log(`Resueltas en F2.1: ${resueltasF21}`);
console.log(`Resueltas en F2.2: ${resueltasF22}`);
console.log(`PENDIENTE: ${pendientes}`);
console.log(`Errores de red: ${errores}`);

console.log(`\nDe las ${resueltasF22} resueltas en F2.2, por fuente:`);
console.log(`  Solo URLScan.io (señal sin overlap conocido con F1): ${soloUrlscan}`);
console.log(`  Solo VirusTotal (posible overlap con F1): ${soloVT}`);
console.log(`  Ambas fuentes coincidieron: ${ambas}`);
console.log(`\nCota conservadora de detección adicional genuina (soloUrlscan + ambas): ${soloUrlscan + ambas}/${urls.length} (${(((soloUrlscan + ambas) / urls.length) * 100).toFixed(1)}%)`);