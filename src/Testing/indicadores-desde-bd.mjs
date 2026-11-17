/**
 * Cuenta los indicadores de F2.2 guardados en la tabla analisis para las URLs de una muestra.
 * Para cada URL toma el análisis más reciente dentro de la ventana de fechas.
 *
 * Uso: node indicadores-desde-bd.mjs <urls.txt> [--desde 2026-09-25] [--hasta 2026-09-28]
 * Requiere: npm i pg, variables DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD (RDS encendida)
 * y normalizarUrl.mjs en la misma carpeta.
 */
import pg from 'pg';
import { readFileSync } from 'fs';
import { normalizarURL } from './normalizarUrl.mjs';

const args = process.argv.slice(2);
const archivo = args[0];
const opcion = (nombre, porDefecto) => {
  const i = args.indexOf(`--${nombre}`);
  return i >= 0 ? args[i + 1] : porDefecto;
};
const desde = opcion('desde', '1970-01-01');
const hasta = opcion('hasta', '2100-01-01');

if (!archivo) {
  console.error('Uso: node indicadores-desde-bd.mjs <urls.txt> [--desde AAAA-MM-DD] [--hasta AAAA-MM-DD]');
  process.exit(1);
}

const INDICADORES = [
  ['urlscan_verdict_malicioso', 'URLScan.io'],
  ['urlscan_scan_eliminado', 'URLScan.io'],
  ['redireccion_detectada', 'URLScan.io'],
  ['categorias_riesgo', 'URLScan.io'],
  ['virustotal_motores_maliciosos', 'VirusTotal'],
  ['virustotal_motores_sospechosos', 'VirusTotal'],
];
const tex = (s) => String(s).replace(/_/g, '\\_');

const urls = [];
for (const linea of readFileSync(archivo, 'utf-8').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'))) {
  try {
    urls.push(normalizarURL(linea).urlNormalizada);
  } catch {
    console.warn('URL no válida, se omite:', linea);
  }
}
const unicas = [...new Set(urls)];

const pool = new pg.Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 8000,
});

try {
  const { rows } = await pool.query(
    `SELECT DISTINCT ON (url) url, veredicto_final, filtro_decisivo, indicadores_f2_2, created_at
     FROM analisis
     WHERE url = ANY($1) AND created_at >= $2 AND created_at < $3
     ORDER BY url, created_at DESC`,
    [unicas, desde, hasta]
  );

  const conteo = {};
  const porFiltro = {};
  for (const r of rows) {
    porFiltro[r.filtro_decisivo ?? 'PENDIENTE'] = (porFiltro[r.filtro_decisivo ?? 'PENDIENTE'] ?? 0) + 1;
    const lista = typeof r.indicadores_f2_2 === 'string' ? JSON.parse(r.indicadores_f2_2) : r.indicadores_f2_2 ?? [];
    for (const nombre of new Set(lista.map((i) => i.indicador))) conteo[nombre] = (conteo[nombre] ?? 0) + 1;
  }

  console.log(`URLs de la muestra: ${unicas.length} | con análisis en la ventana: ${rows.length}`);
  if (rows.length < unicas.length) console.log('Aviso: faltan análisis; revisa las fechas --desde/--hasta.');
  console.log('Por filtro decisivo:', porFiltro);
  console.log('Conteo de indicadores (URLs en las que aparece):', conteo);

  console.log('\n--- Filas LaTeX (Indicador & Fuente & URLs & Proporción) ---');
  for (const [nombre, fuente] of INDICADORES) {
    const x = conteo[nombre] ?? 0;
    console.log(`\\texttt{${tex(nombre)}} & ${fuente} & ${x} & ${((x / unicas.length) * 100).toFixed(0)}\\% \\\\ \\hline`);
  }
} finally {
  await pool.end();
}
