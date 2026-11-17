/**
 * Filtro F2.3 — Vista previa visual segura (Browser Isolation)
 * Migra el screenshot generado por URLScan.io durante F2.2 a S3 propio,
 * devolviendo una URL firmada de vida corta en vez de exponer el enlace
 * de urlscan.io directamente. Degradación progresiva: si algo falla,
 * simplemente no hay screenshot — nunca bloquea el veredicto.
 */

import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { randomUUID } from 'crypto';

const s3 = new S3Client({});
const BUCKET = process.env.SCREENSHOTS_BUCKET;
const URL_FIRMADA_EXPIRACION_SEGUNDOS = 3600; // 1h — el objeto en sí lo borra el lifecycle del bucket a las 24h
const TIMEOUT_DESCARGA_MS = 6000;
const TIEMPO_MINIMO_UTIL_MS = 1000; // si queda menos que esto, ni se intenta

const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47]);
const MAX_BYTES = 5 * 1024 * 1024;
const REGEX_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function sinCaptura(motivo, detalle = null) {
  console.warn(JSON.stringify({ evento: 'f23_sin_captura', motivo, detalle }));
  return { signedUrl: null, s3Key: null, motivo, detalle };
}

/**
 * Siempre devuelve un objeto; si no hay captura, signedUrl y s3Key son null
 * y `motivo` explica por qué.
 *
 * @param {string|null} screenshotUrlOrigen - task.screenshotURL devuelto por URLScan.io en F2.2
 * @param {string|null} uuid - uuid del scan, solo para reintento cuando el polling no terminó
 * @param {number} [deadline] - epoch ms límite para esta etapa (acota el timeout de descarga)
 */
export async function generarVistaPreviaSegura(screenshotUrlOrigen, uuid, deadline = Infinity) {
  let origen = screenshotUrlOrigen ?? null;
  if (!origen && uuid) {
    if (!REGEX_UUID.test(uuid)) return sinCaptura('uuid_invalido');
    origen = `https://urlscan.io/screenshots/${uuid}.png`;
  }
  if (!origen) return sinCaptura('sin_origen_captura');

  // Validar el origen efectivo (no solo el parámetro): protege contra SSRF
  let parsed;
  try { parsed = new URL(origen); }
  catch { return sinCaptura('captura_url_invalida'); }
  if (parsed.protocol !== 'https:' || parsed.hostname !== 'urlscan.io') {
    return sinCaptura('captura_host_no_permitido', parsed.hostname);
  }

  if (!BUCKET) return sinCaptura('bucket_no_configurado');

  const timeoutMs = Math.min(TIMEOUT_DESCARGA_MS, deadline - Date.now());
  if (timeoutMs < TIEMPO_MINIMO_UTIL_MS) return sinCaptura('sin_tiempo_para_captura');

  try {
    // AbortSignal.timeout cubre headers Y lectura del body
    const resp = await fetch(origen, { signal: AbortSignal.timeout(timeoutMs) });
    if (!resp.ok) {
      const cuerpo = (await resp.text().catch(() => '')).slice(0, 200);
      return sinCaptura(`descarga_http_${resp.status}`, cuerpo);
    }

    const declarado = Number(resp.headers.get('content-length'));
    if (declarado > MAX_BYTES) return sinCaptura('captura_demasiado_grande', String(declarado));

    const bytes = Buffer.from(await resp.arrayBuffer());
    if (bytes.length > MAX_BYTES || !bytes.subarray(0, 4).equals(PNG_MAGIC)) {
      return sinCaptura('descarga_no_es_png', resp.headers.get('content-type'));
    }

    const s3Key = `screenshots/${randomUUID()}.png`;
    await s3.send(new PutObjectCommand({ Bucket: BUCKET, Key: s3Key, Body: bytes, ContentType: 'image/png' }));
    const signedUrl = await getSignedUrl(
      s3,
      new GetObjectCommand({ Bucket: BUCKET, Key: s3Key }),
      { expiresIn: URL_FIRMADA_EXPIRACION_SEGUNDOS }
    );
    return { signedUrl, s3Key, motivo: null, detalle: null };
  } catch (err) {
    const esTimeout = err.name === 'AbortError' || err.name === 'TimeoutError';
    return sinCaptura('f23_excepcion', esTimeout ? 'timeout' : err.message);
  }
}

export async function regenerarUrlFirmada(s3Key) {
  if (!s3Key || !BUCKET) return null;
  try {
    return await getSignedUrl(
      s3,
      new GetObjectCommand({ Bucket: BUCKET, Key: s3Key }),
      { expiresIn: URL_FIRMADA_EXPIRACION_SEGUNDOS }
    );
  } catch (err) {
    console.error('No se pudo regenerar URL firmada del screenshot cacheado:', err);
    return null;
  }
}