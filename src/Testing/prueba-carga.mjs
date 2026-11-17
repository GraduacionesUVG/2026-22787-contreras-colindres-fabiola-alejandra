/**
 * Control de tasa de API Gateway (M11).
 * Envía solicitudes con cuerpo vacío ({}), que la Lambda rechaza con 400 sin llamar a
 * APIs externas ni a la base de datos. Si API Gateway aplica el límite, el exceso recibe
 * 429 sin llegar a la Lambda.
 *
 * Uso: node prueba-carga.mjs <invoke-url> [--n 100] [--rps 20] [--seg 10] [--rate 5] [--burst 10] [--ruta /analyze]
 *   --n       tamaño de la ráfaga simultánea (fase 1)
 *   --rps     solicitudes por segundo de la fase sostenida (fase 2)
 *   --seg     duración de la fase sostenida
 *   --rate / --burst  límites configurados en la etapa (solo para calcular la capacidad aproximada)
 */
const args = process.argv.slice(2);
const base = (args[0] ?? '').replace(/\/$/, '');
const opcion = (nombre, porDefecto) => {
  const i = args.indexOf(`--${nombre}`);
  return i >= 0 ? args[i + 1] : porDefecto;
};
const n = Number(opcion('n', 100));
const rps = Number(opcion('rps', 20));
const seg = Number(opcion('seg', 10));
const rate = Number(opcion('rate', 0));
const burst = Number(opcion('burst', 0));
const ruta = opcion('ruta', '/analyze');

if (!base) {
  console.error('Uso: node prueba-carga.mjs <invoke-url> [--n 100] [--rps 20] [--seg 10] [--rate 5] [--burst 10] [--ruta /analyze]');
  process.exit(1);
}

const esperar = (ms) => new Promise((r) => setTimeout(r, ms));

async function enviar() {
  try {
    const res = await fetch(`${base}${ruta}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
      signal: AbortSignal.timeout(30000),
    });
    await res.text();
    return res.status;
  } catch {
    return 0;
  }
}

function informe(titulo, codigos, duracion) {
  const conteo = {};
  for (const c of codigos) conteo[c] = (conteo[c] ?? 0) + 1;
  const r429 = conteo[429] ?? 0;
  console.log(`\n${titulo}`);
  console.log(`  Solicitudes enviadas: ${codigos.length} en ${duracion.toFixed(1)} s`);
  console.log('  Códigos HTTP:', conteo);
  console.log(`  Respuestas 429: ${r429} | procesadas por la Lambda (no 429): ${codigos.length - r429}`);
  if (rate > 0 && burst > 0) {
    console.log(`  Capacidad máxima aproximada (burst + rate x duración): ${Math.round(burst + rate * duracion)}`);
  }
}

console.log(`Ruta de prueba: ${ruta} (cuerpo {}: la Lambda responde 400 sin usar APIs externas ni BD)`);

let t0 = Date.now();
const rafaga = await Promise.all(Array.from({ length: n }, () => enviar()));
informe(`Fase 1: ráfaga de ${n} solicitudes simultáneas`, rafaga, (Date.now() - t0) / 1000);

await esperar(5000);

t0 = Date.now();
const promesas = [];
for (let i = 0; i < rps * seg; i++) {
  promesas.push(enviar());
  await esperar(1000 / rps);
}
const sostenida = await Promise.all(promesas);
informe(`Fase 2: ${rps} solicitudes por segundo durante ${seg} s`, sostenida, (Date.now() - t0) / 1000);

console.log('\nOpcional: la métrica Invocations de la Lambda en esta ventana debería coincidir con las respuestas que no fueron 429.');
