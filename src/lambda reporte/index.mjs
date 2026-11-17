/**
 * Endpoint de reportes de QR malicioso.
 * Guarda el reporte en la tabla `reportes`, vinculado opcionalmente a un
 * análisis previo (analisis_id).
 *
 * NOTA: PhishTank no expone una API pública de envío (solo `checkurl` de
 * consulta) — la "retroalimentación a blacklists colaborativas" descrita
 * en el protocolo no es técnicamente posible vía API pública. El reporte
 * queda persistido en `reportes` como fuente de verdad propia; no se
 * intenta ningún envío automático a terceros.
 */
import pg from 'pg';
import { normalizarURL } from './normalizarUrl.mjs';

const pool = new pg.Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 5000,
});

export const handler = async (event) => {
  try {
    let body;
    try {
      body = event.body ? JSON.parse(event.body) : {};
    } catch {
      return response(400, { error: 'INVALID_INPUT', message: 'El cuerpo de la solicitud debe ser JSON válido.' });
    }
    if (body === null || typeof body !== 'object' || Array.isArray(body)) {
      return response(400, { error: 'INVALID_INPUT', message: 'El cuerpo de la solicitud debe ser un objeto JSON.' });
    }
    const { url, motivo, analisis_id } = body;

    if (!url || typeof url !== 'string') {
      return response(400, {
        error: 'INVALID_INPUT',
        message: 'El campo "url" es requerido y debe ser un string.',
      });
    }

    let urlInfo;
    try {
      urlInfo = normalizarURL(url);
    } catch {
      return response(400, {
        error: 'URL_INVALIDA',
        message: 'La URL no es válida o usa un esquema no soportado (solo http/https).',
      });
    }

    if (analisis_id !== undefined && analisis_id !== null && 
      (!Number.isInteger(analisis_id) || analisis_id < 1 || analisis_id > 2147483647)) {
      return response(400, { error: 'INVALID_INPUT', message: '"analisis_id" debe ser un entero positivo si se incluye.' });
    }

    try {
      const { rows } = await pool.query(
        `INSERT INTO reportes (analisis_id, url_reportada, motivo, created_at)
         VALUES ($1, $2, $3, NOW())
         RETURNING id, created_at`,
        [analisis_id ?? null, urlInfo.urlNormalizada, motivo ?? null]
      );
      return response(200, {
        reporte_id: rows[0].id,
        url: urlInfo.urlNormalizada,
        recibido_en: rows[0].created_at,
        mensaje: 'Reporte recibido. Gracias por ayudar a mejorar la detección.',
      });
    } catch (err) {
      if (err.code === '23503') { // violación de foreign key
        return response(400, {
          error: 'ANALISIS_ID_INVALIDO',
          message: 'El "analisis_id" proporcionado no corresponde a ningún análisis existente.',
        });
      }
      console.error('Error guardando reporte (¿RDS no disponible?):', err);
      return response(500, { error: 'INTERNAL_ERROR', message: 'No se pudo guardar el reporte en este momento.' });
    }

  } catch (err) {
    console.error(err);
    return response(500, { error: 'INTERNAL_ERROR', message: 'Error inesperado procesando la solicitud.' });
  }
};

function response(statusCode, body) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    body: JSON.stringify(body),
  };
}