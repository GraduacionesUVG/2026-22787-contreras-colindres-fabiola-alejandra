/**
 * Validación de entrada (M10).
 * Envía solicitudes inválidas a /analyze y /report y registra código HTTP y mensaje.
 * Un caso cumple si responde 400 con un mensaje descriptivo.
 *
 * Uso: node probar-validacion.mjs <invoke-url>
 * Imprime una tabla y las filas en formato LaTeX
 * (Caso & Endpoint & Entrada & Código & Mensaje & Cumple).
 */
const base = (process.argv[2] ?? '').replace(/\/$/, '');
if (!base) {
  console.error('Uso: node probar-validacion.mjs <invoke-url>');
  process.exit(1);
}

const casos = [
  { id: 'V1', ruta: '/analyze', desc: 'Cuerpo vacío ({})', cuerpo: '{}' },
  { id: 'V2', ruta: '/analyze', desc: 'Campo url con tipo incorrecto (número)', cuerpo: '{"url":123}' },
  { id: 'V3', ruta: '/analyze', desc: 'Campo url vacío', cuerpo: '{"url":""}' },
  { id: 'V4', ruta: '/analyze', desc: 'Esquema no soportado (ftp)', cuerpo: '{"url":"ftp://ejemplo.com/archivo"}' },
  { id: 'V5', ruta: '/analyze', desc: 'Esquema javascript', cuerpo: '{"url":"javascript:alert(1)"}' },
  { id: 'V6', ruta: '/analyze', desc: 'URL incompleta (http://)', cuerpo: '{"url":"http://"}' },
  { id: 'V7', ruta: '/analyze', desc: 'Cuerpo que no es JSON válido', cuerpo: '{url: sin comillas' },
  { id: 'V8', ruta: '/analyze', desc: 'Cuerpo JSON que no es un objeto (null)', cuerpo: 'null' },
  { id: 'V9', ruta: '/report', desc: 'Reporte sin url', cuerpo: '{"motivo":"prueba"}' },
  { id: 'V10', ruta: '/report', desc: 'Reporte con URL inválida', cuerpo: '{"url":"no es una url"}' },
  { id: 'V11', ruta: '/report', desc: 'analisis_id con tipo incorrecto', cuerpo: '{"url":"https://ejemplo.com","analisis_id":"abc"}' },
  { id: 'V12', ruta: '/report', desc: 'analisis_id inexistente', cuerpo: '{"url":"https://ejemplo.com","analisis_id":999999}' },
  { id: 'V13', ruta: '/report', desc: 'analisis_id fuera del rango de enteros', cuerpo: '{"url":"https://ejemplo.com","analisis_id":99999999999}' },
  { id: 'V14', ruta: '/report', desc: 'Cuerpo que no es JSON válido', cuerpo: 'esto no es json' },
];

const mapa = {
  '\\': '\\textbackslash{}', '&': '\\&', '%': '\\%', '$': '\\$', '#': '\\#',
  '_': '\\_', '{': '\\{', '}': '\\}', '~': '\\textasciitilde{}', '^': '\\textasciicircum{}', '"': '\\textquotedbl{}',
};
const tex = (s) => String(s).replace(/[\\&%$#_{}~^"]/g, (c) => mapa[c]);

const filas = [];
for (const c of casos) {
  let status = 0;
  let texto = '';
  let json = null;
  try {
    const res = await fetch(`${base}${c.ruta}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: c.cuerpo,
      signal: AbortSignal.timeout(60000),
    });
    status = res.status;
    texto = await res.text();
    try { json = JSON.parse(texto); } catch { /* respuesta que no es JSON */ }
  } catch (err) {
    texto = `error de red (${err.name})`;
  }
  const mensaje = json?.message ?? texto.slice(0, 80);
  const codigoError = json?.error ?? '';
  const cumple = status === 400 && typeof json?.message === 'string' && json.message.length > 0;
  filas.push({ ...c, status, codigoError, mensaje, cumple });
  await new Promise((r) => setTimeout(r, 300));
}

console.table(filas.map(({ id, ruta, desc, status, codigoError, cumple }) => ({ id, ruta, desc, status, codigoError, cumple })));
console.log(`\nCumplen (400 con mensaje descriptivo): ${filas.filter((f) => f.cumple).length}/${filas.length}`);
const fallan = filas.filter((f) => !f.cumple);
if (fallan.length) {
  console.log('\nNo cumplen:');
  for (const f of fallan) console.log(`  ${f.id}: ${f.desc} -> HTTP ${f.status} ${f.codigoError} ${f.mensaje}`);
}

console.log('\n--- Filas LaTeX ---');
for (const f of filas) {
  console.log(`${f.id} & \\texttt{${tex(f.ruta)}} & ${tex(f.desc)} & ${f.status} & ${tex(f.mensaje)} & ${f.cumple ? 'Sí' : 'No'} \\\\ \\hline`);
}
