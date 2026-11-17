/**
 * Casos controlados (M12): envía cada página de prueba a /analyze, guarda la captura en
 * capturas/<id>.png y resume lo obtenido para la tabla de resultados.
 *
 * Uso: node probar-casos.mjs <invoke-url> <casos.json>
 *
 * Formato de casos.json (los campos esperado_* son opcionales):
 * [
 *   { "id": "C1", "url": "https://mi-prueba.example/c1", "esperado_indicadores": ["redireccion_detectada"] },
 *   { "id": "C5", "url": "https://mi-prueba.example/c5" },
 *   { "id": "C6", "url": "https://mi-prueba.example/c6", "esperado_veredicto": "PENDIENTE" }
 * ]
 * Sin campos esperado_*, la columna "Coincide" queda para revisión manual.
 *
 * Si repites un caso en menos de 24 h (7 días si dio SOSPECHOSO), el endpoint responde desde
 * caché. Para forzar un análisis nuevo borra su fila:
 *   DELETE FROM analisis WHERE url = '<url normalizada>';
 */
import { readFileSync, writeFileSync, mkdirSync } from 'fs';

const [, , invokeUrlRaw, archivoCasos] = process.argv;
const invokeUrl = (invokeUrlRaw ?? '').replace(/\/$/, '');
if (!invokeUrl || !archivoCasos) {
  console.error('Uso: node probar-casos.mjs <invoke-url> <casos.json>');
  process.exit(1);
}

const casos = JSON.parse(readFileSync(archivoCasos, 'utf-8'));
mkdirSync('capturas', { recursive: true });

const mapa = {
  '\\': '\\textbackslash{}', '&': '\\&', '%': '\\%', '$': '\\$', '#': '\\#',
  '_': '\\_', '{': '\\{', '}': '\\}', '~': '\\textasciitilde{}', '^': '\\textasciicircum{}', '"': '\\textquotedbl{}',
};
const tex = (s) => String(s).replace(/[\\&%$#_{}~^"]/g, (c) => mapa[c]);

function evaluar(caso, data) {
  const ind = (data?.indicadores_f2_2 ?? []).map((i) => i.indicador);
  const pruebas = [];
  if (caso.esperado_veredicto) pruebas.push(data?.veredicto_final === caso.esperado_veredicto);
  if (caso.esperado_indicadores?.length) pruebas.push(caso.esperado_indicadores.every((x) => ind.includes(x)));
  if (pruebas.length === 0) return 'REVISAR';
  return pruebas.every(Boolean) ? 'Sí' : 'No';
}

for (const caso of casos) {
  let status = 0;
  let data = null;
  try {
    const res = await fetch(`${invokeUrl}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: caso.url, resultadoF1: 'INCIERTO' }),
      signal: AbortSignal.timeout(60000),
    });
    status = res.status;
    data = await res.json().catch(() => null);
  } catch (err) {
    console.error(`${caso.id}: error de red (${err.name})`);
  }

  const indicadores = (data?.indicadores_f2_2 ?? []).map((i) => i.indicador);
  const criterios = (data?.criterios_f2_1 ?? []).map((c) => c.criterio);

  let captura = 'sin captura';
  if (data?.screenshot_url) {
    try {
      const img = await fetch(data.screenshot_url, { signal: AbortSignal.timeout(20000) });
      if (img.ok) {
        writeFileSync(`capturas/${caso.id}.png`, Buffer.from(await img.arrayBuffer()));
        captura = `capturas/${caso.id}.png`;
      }
    } catch { /* se deja "sin captura" */ }
  }

  const coincide = evaluar(caso, data);
  const veredicto = data?.veredicto_final ?? `error HTTP ${status}`;
  const obtenido = `${veredicto}${indicadores.length ? '; ' + indicadores.join(', ') : ''}`;

  console.log(`\n=== ${caso.id} ===`);
  console.log(`URL: ${caso.url}`);
  console.log(`Veredicto: ${veredicto} (filtro: ${data?.filtro_decisivo ?? 'ninguno'}) | puntaje F2.1: ${data?.score_heuristico ?? 'n/a'}`);
  console.log(`Criterios F2.1: ${criterios.join(', ') || 'ninguno'}`);
  console.log(`Indicadores F2.2: ${indicadores.join(', ') || 'ninguno'}`);
  console.log(`Captura: ${captura}`);
  if (data?.desde_cache) console.log('AVISO: respuesta desde caché; no es un análisis nuevo (ver la nota del encabezado).');
  console.log(`Celdas para la tabla: ${tex(obtenido)} & ${coincide === 'REVISAR' ? '\\textbf{[REVISAR]}' : coincide} \\\\ \\hline`);
}
