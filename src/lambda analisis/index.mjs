import pg from 'pg';
import { normalizarURL } from './normalizarUrl.mjs';
import { calcularScoreHeuristico, extraerDominioRaiz } from './heuristica.mjs';
import { obtenerAntiguedadDominio } from './whois.mjs';
import { analizarSandbox } from './sandbox.mjs';
import { generarVistaPreviaSegura, regenerarUrlFirmada } from './browserIsolation.mjs';

/**
 * Endpoint de análisis
 * Recibe la URL + resultado de F1 (evaluado por el frontend/Majo).
 * Normaliza la URL (RFC 3986), enruta la cascada: si F1 ya dio veredicto
 * definitivo, corta ahí. Si F1 devuelve INCIERTO, corre el motor heurístico
 * F2.1. Si F2.1 tampoco es concluyente (score <= 60), escala a F2.2 (sandbox)
 * y F2.3 (vista previa visual).
 *
 * Degradación progresiva: si WHOIS, URLScan o VirusTotal fallan o agotan el
 * plazo, ese resultado simplemente no se incluye; el veredicto se apoya en
 * lo que sí respondió (como mínimo, el score heurístico F2.1).
 */

// Presupuesto de tiempo (ajustar al timeout real de Lambda y de API Gateway)
const PRESUPUESTO_TOTAL_MS = 35000;
const MARGEN_F22_MS = 5000; // lo que se reserva tras F2.2: F2.3 + INSERT + respuesta
const MARGEN_F23_MS = 4000;  // lo que se reserva tras F2.3: INSERT + respuesta

// Descarga ejecutable confirmada + score heurístico base (sin contar la extensión) por encima de esto => MALICIOSO
const UMBRAL_SCORE_BASE_DESCARGA = 30;

// Resultado de F2.2 cuando el módulo entero falla de forma inesperada
const SANDBOX_NO_DISPONIBLE = {
  veredicto: 'PENDIENTE',
  indicadores: [],
  uuid: null,
  descargaEjecutable: false,
  screenshotUrl: null,
  captura: { disponible: false, motivo: 'sandbox_error', detalle: null },
  fuentes: {
    urlscan: { disponible: false, veredicto: null },
    virustotal: { disponible: false, veredicto: null },
  },
};

// El pool se crea una sola vez fuera del handler, así Lambda lo reutiliza
// entre invocaciones "calientes" en vez de abrir una conexión nueva cada vez.
const pool = new pg.Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: { rejectUnauthorized: false }, // RDS requiere SSL
  connectionTimeoutMillis: 5000, // si RDS está pausada/inalcanzable, falla rápido en vez de colgar el request
});

export const handler = async (event) => {
  const inicioRequest = Date.now();

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

    const { url, resultadoF1 } = body;

    if (!url || typeof url !== 'string') {
      return response(400, {
        error: 'INVALID_INPUT',
        message: 'El campo "url" es requerido y debe ser un string.',
      });
    }

    // Normalización y parsing — antes de cualquier análisis de la cascada
    let urlInfo;
    try {
      urlInfo = normalizarURL(url);
    } catch (err) {
      return response(400, {
        error: 'URL_INVALIDA',
        message: 'La URL no es válida o usa un esquema no soportado (solo http/https).',
      });
    }

    // Estados válidos que puede traer F1
    const ESTADOS_VALIDOS = ['SEGURO', 'MALICIOSO', 'INCIERTO'];
    const estadoF1 = ESTADOS_VALIDOS.includes(resultadoF1) ? resultadoF1 : 'INCIERTO';

    // Corte anticipado: si F1 ya fue concluyente, no hace falta seguir la cascada
    if (estadoF1 === 'SEGURO' || estadoF1 === 'MALICIOSO') {
      const resultado = {
        url: urlInfo.urlNormalizada,
        dominio: urlInfo.dominio,
        veredicto_final: estadoF1,
        filtro_decisivo: 'F1',
      };
      await guardarAnalisis(resultado);
      return response(200, resultado);
    }

    // Caché. Si RDS no responde, lo recordamos para no gastar otros 5 s en el INSERT final.
    let rdsDisponible = true;
    let cacheado = null;
    try {
      cacheado = await buscarAnalisisReciente(urlInfo.urlNormalizada);
    } catch (err) {
      rdsDisponible = false;
      console.error('Caché no disponible (¿RDS no disponible?), se continúa sin ella:', err);
    }

    if (cacheado) {
      const screenshotUrlCache = await regenerarUrlFirmada(cacheado.screenshot_s3_key);
      console.log("Caché disponible, screenshot generada: ", screenshotUrlCache)
      return response(200, {
        url: urlInfo.urlNormalizada,
        dominio: urlInfo.dominio,
        veredicto_final: cacheado.veredicto_final,
        filtro_decisivo: cacheado.filtro_decisivo,
        score_heuristico: Number(cacheado.score_heuristico), // normaliza el string de NUMERIC a number
        criterios_f2_1: cacheado.criterios_f2_1,
        ...(cacheado.indicadores_f2_2 && { indicadores_f2_2: cacheado.indicadores_f2_2 }),
        ...(screenshotUrlCache !== null && { screenshot_url: screenshotUrlCache }),
        desde_cache: true,
      });
    }

    // Filtro F2.1: antigüedad de dominio (WHOIS sobre dominio raíz + caché) + motor heurístico.
    // obtenerAntiguedadDominio ya no lanza, pero el .catch es un cinturón extra:
    // WHOIS nunca debe impedir que el heurístico se calcule.
    const dominioRaiz = extraerDominioRaiz(urlInfo.dominio);
    const antiguedadDominio = await obtenerAntiguedadDominio(dominioRaiz).catch(() => null);
    const heuristica = calcularScoreHeuristico(urlInfo, antiguedadDominio);
    const heuristicaSospechosa = heuristica.veredicto === 'SOSPECHOSO';

    // Corte anticipado por F2.1, salvo que la ruta apunte a un ejecutable: en ese caso se
    // sigue a F2.2 para confirmar si realmente hay una descarga (eso puede escalar a MALICIOSO).
    if (heuristicaSospechosa && !heuristica.ejecutableEnRuta) {
      const resultado = {
        url: urlInfo.urlNormalizada,
        dominio: urlInfo.dominio,
        veredicto_final: 'SOSPECHOSO',
        filtro_decisivo: 'F2.1',
        score_heuristico: heuristica.score,
        criterios_f2_1: heuristica.criteriosActivados,
      };
      if (rdsDisponible) await guardarAnalisis(resultado);
      return response(200, resultado);
    }

    // F2.1 no concluyente (score <= 60) -> escala a F2.2
    const deadlineF22 = inicioRequest + PRESUPUESTO_TOTAL_MS - MARGEN_F22_MS;
    const deadlineF23 = inicioRequest + PRESUPUESTO_TOTAL_MS - MARGEN_F23_MS;
    const inicioF22 = Date.now();

    let resultadoSandbox;
    try {
      resultadoSandbox = await analizarSandbox(urlInfo.urlNormalizada, deadlineF22);
    } catch (err) {
      console.error('F2.2 falló de forma inesperada, se continúa solo con F2.1:', err);
      resultadoSandbox = SANDBOX_NO_DISPONIBLE;
    }
    const plazoAgotado = Date.now() >= deadlineF22;

    const urlscanOk = resultadoSandbox.fuentes.urlscan.disponible;
    const vtOk = resultadoSandbox.fuentes.virustotal.disponible;
    const algunaFuente = urlscanOk || vtOk;

    // Veredicto final = el más grave entre F2.2 y F2.1 (MALICIOSO > SOSPECHOSO > PENDIENTE).
    // Descarga ejecutable + al menos una señal heurística independiente de la extensión => MALICIOSO.
    const descargaConfirmada = resultadoSandbox.descargaEjecutable
      && heuristica.scoreBase > UMBRAL_SCORE_BASE_DESCARGA;
    let veredictoFinal, filtroDecisivo;
    if (resultadoSandbox.veredicto === 'MALICIOSO' || descargaConfirmada) {
      veredictoFinal = 'MALICIOSO'; filtroDecisivo = 'F2.2';
    } else if (resultadoSandbox.veredicto === 'SOSPECHOSO') {
      veredictoFinal = 'SOSPECHOSO'; filtroDecisivo = 'F2.2';
    } else if (heuristicaSospechosa) {
      veredictoFinal = 'SOSPECHOSO'; filtroDecisivo = 'F2.1'; // F2.2 no confirmó nada, pero F2.1 ya lo marcaba
    } else {
      veredictoFinal = 'PENDIENTE'; filtroDecisivo = null;
    }
    // Si ningún proveedor respondió, "no hay datos" (null) no debe leerse como "analizado y limpio" ([])
    const indicadoresF22 = algunaFuente ? resultadoSandbox.indicadores : null;

    const MOTIVOS_REINTENTABLES = ['urlscan_sin_respuesta_a_tiempo', 'destino_inaccesible'];
    const reintentarPorUuid = MOTIVOS_REINTENTABLES.includes(resultadoSandbox.captura.motivo);
    const hayOrigen = Boolean(resultadoSandbox.screenshotUrl) || (reintentarPorUuid && Boolean(resultadoSandbox.uuid));

    const vistaPrevia = hayOrigen
      ? await generarVistaPreviaSegura(
          resultadoSandbox.screenshotUrl,
          reintentarPorUuid ? resultadoSandbox.uuid : null,
          deadlineF23
        )
      : null;

    const screenshotUrl = vistaPrevia?.signedUrl ?? null;
    const screenshotS3Key = vistaPrevia?.s3Key ?? null;
    // El motivo de F2.2 es el más informativo; el de F2.3 solo aplica si F2.2 sí entregó origen
    const capturaMotivo = screenshotUrl ? null
      : (resultadoSandbox.captura?.motivo ?? vistaPrevia?.motivo ?? 'sin_captura');

    console.log('METRICA ' + JSON.stringify({
      t_f22_ms: Date.now() - inicioF22,
      plazo_agotado: plazoAgotado,
      urlscan_ok: urlscanOk,
      vt_ok: vtOk,
      captura_motivo: capturaMotivo,
    }));

    if (rdsDisponible) {
      try {
        await pool.query(
          `INSERT INTO analisis
            (url, dominio, veredicto_final, filtro_decisivo, score_heuristico,
             criterios_f2_1, indicadores_f2_2, screenshot_s3_key, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
          [
            urlInfo.urlNormalizada,
            urlInfo.dominio,
            veredictoFinal,
            filtroDecisivo,
            heuristica.score,
            JSON.stringify(heuristica.criteriosActivados),
            indicadoresF22 ? JSON.stringify(indicadoresF22) : null,
            screenshotS3Key,
          ]
        );
      } catch (err) {
        console.error('No se pudo persistir el análisis F2.2/F2.3 (¿RDS no disponible?):', err);
        // no relanzamos — el veredicto ya calculado sigue siendo válido para el usuario
      }
    }

    return response(200, {
      url: urlInfo.urlNormalizada,
      dominio: urlInfo.dominio,
      veredicto_final: veredictoFinal,
      filtro_decisivo: filtroDecisivo,
      score_heuristico: heuristica.score,
      criterios_f2_1: heuristica.criteriosActivados,
      ...(indicadoresF22 !== null && { indicadores_f2_2: indicadoresF22 }),
      // Qué proveedores aportaron datos: el frontend puede ocultar los que no
      fuentes_f2_2: { urlscan: urlscanOk, virustotal: vtOk },
      f2_2_completo: urlscanOk && vtOk,
      ...(veredictoFinal === 'PENDIENTE' && {
        mensaje: algunaFuente
          ? 'F1, F2.1 y F2.2 no concluyentes'
          : 'F2.2 no disponible (timeout o proveedores caídos); resultado basado solo en F2.1',
      }),
      ...(screenshotUrl !== null && { screenshot_url: screenshotUrl }),
      ...(capturaMotivo && { captura_motivo: capturaMotivo }),
    });

  } catch (err) {
    console.error(err);
    return response(500, {
      error: 'INTERNAL_ERROR',
      message: 'Error inesperado procesando la solicitud.',
    });
  }
};

/**
 * Lanza si la consulta a RDS falla (el handler lo captura y marca rdsDisponible = false).
 * Devuelve null si no hay análisis reciente utilizable.
 */
async function buscarAnalisisReciente(urlNormalizada) {
  const { rows } = await pool.query(
    `SELECT veredicto_final, filtro_decisivo, score_heuristico,
            criterios_f2_1, indicadores_f2_2, screenshot_s3_key, created_at
     FROM analisis
     WHERE url = $1
     ORDER BY created_at DESC
     LIMIT 1`,
    [urlNormalizada]
  );
  if (rows.length === 0) return null;

  const analisis = rows[0];
  const horasDesdeAnalisis = (Date.now() - new Date(analisis.created_at).getTime()) / (1000 * 60 * 60);
  const esMalicioso = analisis.veredicto_final === 'SOSPECHOSO' || analisis.veredicto_final === 'MALICIOSO';
  const ttlHoras = esMalicioso ? 168 : 0; // 7 días vs sin caché

  if (horasDesdeAnalisis > ttlHoras) return null; // expiró, re-analizar
  return analisis;
}

async function guardarAnalisis(resultado) {
  try {
    await pool.query(
      `INSERT INTO analisis (url, dominio, veredicto_final, filtro_decisivo, score_heuristico, criterios_f2_1)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        resultado.url,
        resultado.dominio,
        resultado.veredicto_final,
        resultado.filtro_decisivo,
        resultado.score_heuristico ?? null,
        resultado.criterios_f2_1 ? JSON.stringify(resultado.criterios_f2_1) : null,
      ]
    );
  } catch (err) {
    console.error('No se pudo persistir el análisis (¿RDS no disponible?):', err);
    // no relanzamos — el veredicto ya calculado sigue siendo válido para el usuario
  }
}

function response(statusCode, body) {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
    body: JSON.stringify(body),
  };
}
