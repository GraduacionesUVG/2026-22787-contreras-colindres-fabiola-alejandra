/**
 * Filtro F2.2 — Sandbox dinámico
 * Analiza el comportamiento de la URL en un entorno aislado mediante
 * URLScan.io (renderizado + verdicts) y VirusTotal (agregación de motores).
 * Ambas consultas corren en paralelo dentro de un presupuesto de tiempo
 * compartido (deadline), con degradación progresiva si alguna falla o
 * no termina a tiempo — nunca bloquea al backend.
 *
 * Visibilidad de scans en URLScan.io: "unlisted" (no indexado públicamente),
 * decisión alineada con la política de privacidad del proyecto — las URLs
 * escaneadas por usuarios pueden contener tokens/identificadores.
 */

const URLSCAN_API_KEY = process.env.URLSCAN_API_KEY;
const VT_API_KEY = process.env.VT_API_KEY;

const URLSCAN_POLL_INTERVAL_MS = 5000; // espaciado conservador frente al límite de 6 req/min del plan gratuito
const VT_POLL_INTERVAL_MS = 4000;
const TIMEOUT_REQUEST_MS = 8000; // tope por request individual (siempre acotado además por el deadline)

// Descargas ejecutables: un QR que entrega un instalador/ejecutable directamente no tiene
// justificación legítima. Se evalúa sobre meta.processors.download.data (nombre y tipo MIME).
const EXT_EJECUTABLE = /\.(exe|msi|scr|bat|cmd|ps1|vbs|jar|apk|dmg|pkg|iso|lnk|dll|hta)$/i;
const MIME_EJECUTABLE = /(dosexec|msdownload|msdos-program|x-executable|x-elf|android\.package|java-archive|x-msi|x-mach-binary)/i;
const MAX_DESCARGAS_EN_DETALLE = 5;
const UMBRAL_VT_MALICIOSO = 5; // más de 5 motores maliciosos (sin contar sospechosos) => MALICIOSO

/** Milisegundos que se pueden gastar en un request: min(tope, lo que queda del deadline) */
function msRestantes(deadline, tope = TIMEOUT_REQUEST_MS) {
  return Math.min(tope, deadline - Date.now());
}

/**
 * fetch con timeout que cubre headers Y lectura del body (AbortSignal.timeout
 * se mantiene activo hasta que se consume la respuesta).
 */
async function fetchConTimeout(url, opciones = {}, timeoutMs = TIMEOUT_REQUEST_MS) {
  if (timeoutMs <= 0) {
    const err = new Error('sin_tiempo_restante');
    err.name = 'TimeoutError';
    throw err;
  }
  return fetch(url, { ...opciones, signal: AbortSignal.timeout(timeoutMs) });
}

/** Codifica la URL en base64url sin padding — formato de ID que usa VirusTotal v3 */
function idVirusTotal(url) {
  return Buffer.from(url).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function esperar(ms) {
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)));
}

function esErrorDeTiempo(err) {
  return err?.name === 'AbortError' || err?.name === 'TimeoutError';
}

function sinWww(host) {
  return (host ?? '').toLowerCase().replace(/^www\./, '');
}

// URLScan.io
async function enviarAUrlscan(url, deadline) {
  const resp = await fetchConTimeout('https://urlscan.io/api/v1/scan/', {
    method: 'POST',
    headers: { 'API-Key': URLSCAN_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, visibility: 'unlisted' }),
  }, msRestantes(deadline));

  if (!resp.ok) {
    const cuerpo = await resp.text().catch(() => '');
    const err = new Error(`URLScan submit falló: ${resp.status}`);
    err.status = resp.status;
    err.detalle = cuerpo.slice(0, 300);
    throw err;
  }
  const data = await resp.json();
  return { uuid: data.uuid, resultUrl: data.api }; // data.api = endpoint de resultado
}

async function consultarUrlscan(uuid, deadline) {
  while (Date.now() < deadline) {
    await esperar(Math.min(URLSCAN_POLL_INTERVAL_MS, deadline - Date.now()));

    const timeoutFetch = msRestantes(deadline);
    if (timeoutFetch <= 0) break;

    let resp;
    try {
      resp = await fetchConTimeout(`https://urlscan.io/api/v1/result/${uuid}/`, {
        headers: { 'API-Key': URLSCAN_API_KEY },
      }, timeoutFetch);
    } catch (err) {
      // Un poll individual que falla (red, abort) no debe cortar todo el polling
      console.warn(`URLScan poll falló uuid=${uuid}: ${err.name}`);
      continue;
    }

    if (resp.status === 200) {
      try {
        return await resp.json();
      } catch (err) {
        console.warn(`URLScan body ilegible uuid=${uuid}: ${err.name}`);
        continue;
      }
    }
    // 404 = aún procesando; 429 = límite de tasa, esperar y reintentar dentro del plazo
    if (resp.status === 404 || resp.status === 429) continue;

    // Cualquier otro código (410 eliminado, 400, 5xx, etc.) es terminal:
    // nunca va a convertirse en 200, así que no tiene sentido seguir el loop.
    console.warn(`URLScan resultado no disponible de forma permanente (status ${resp.status})`);
    return resp.status === 410 ? { _eliminado: true } : { _error: `resultado_http_${resp.status}` };
  }
  return { _error: 'sin_respuesta_a_tiempo' };
}

function extraerIndicadoresUrlscan(resultado) {
  if (!resultado) return { disponible: false, indicadores: [], screenshotUrl: null };

  if (resultado._eliminado) {
    return {
      disponible: true,
      veredicto: 'SOSPECHOSO',
      score: null,
      indicadores: [{
        indicador: 'urlscan_scan_eliminado',
        detalle: 'URLScan.io eliminó el scan tras el análisis — comportamiento asociado a contenido confirmado como malicioso',
      }],
      screenshotUrl: null,
    };
  }

  if (resultado._error) {
    return { disponible: false, indicadores: [], screenshotUrl: null, capturaMotivo: `urlscan_${resultado._error}` };
  }

  const reqs = resultado.data?.requests ?? [];
  const errorCarga = reqs.find((r) => r.request?.primaryRequest)?.response?.failed?.errorText;
  const paginaError = reqs.some((r) => r.request?.documentURL?.startsWith('chrome-error://'));
  // Si el enlace entrega un archivo, no hay página que renderizar: el screenshot no aporta nada
  const descargas = resultado.meta?.processors?.download?.data ?? [];
  const descargaEjecutable = descargas.find(
    (d) => EXT_EJECUTABLE.test(d.filename ?? '') || MIME_EJECUTABLE.test(d.mimeType ?? '')
  );
  const cargo = !errorCarga && !paginaError && descargas.length === 0;

  const indicadores = [];
  const verdictoMalicioso = resultado.verdicts?.overall?.malicious === true;
  const score = resultado.verdicts?.overall?.score ?? 0;

  if (verdictoMalicioso) {
    indicadores.push({
      indicador: 'urlscan_verdict_malicioso',
      detalle: `URLScan marca el sitio como malicioso (score: ${score})`,
    });
  }

  const cadenaRedirecciones = resultado.data?.redirects ?? [];
  const dominioOriginal = resultado.page?.domain;

  const redireccionCrossDomain = cadenaRedirecciones.find((r) => {
    try {
      const dominioDestino = new URL(r.to).hostname;

      return dominioDestino !== dominioOriginal;
    } catch {
      return false;
    }
  });

  if (redireccionCrossDomain) {
    indicadores.push({
      indicador: 'redireccion_detectada',
      detalle: `Redirigido a un dominio distinto: ${redireccionCrossDomain.to}`,
    });
  }

  const categorias = resultado.verdicts?.overall?.categories ?? [];
  if (categorias.length > 0) {
    indicadores.push({
      indicador: 'categorias_riesgo',
      detalle: `Categorías: ${categorias.join(', ')}`,
    });
  }

  // Veredicto de los motores de URLScan (verdicts.engines), independiente de verdicts.overall
  const motoresMalicioso = resultado.verdicts?.engines?.malicious === true;
  if (motoresMalicioso) {
    indicadores.push({
      indicador: 'urlscan_motores_maliciosos',
      detalle: `Los motores de URLScan lo marcan como malicioso (score: ${resultado.verdicts.engines.score ?? '?'})`,
    });
  }

  if (descargas.length > 0) {
    // filename viene del servidor atacante: se trunca y el cliente debe tratarlo como texto, no HTML
    const lista = descargas
      .slice(0, MAX_DESCARGAS_EN_DETALLE)
      .map((d) => `${String(d.filename ?? 'archivo').slice(0, 80)} (${String(d.mimeDescription ?? d.mimeType ?? 'tipo desconocido').slice(0, 80)})`)
      .join(', ');
    indicadores.push({
      indicador: 'descarga_automatica_detectada',
      detalle: `El enlace descarga un archivo: ${lista}`,
    });
  }

  // Niveles: overall.malicious => MALICIOSO. Motores, descarga ejecutable o categorías de riesgo => SOSPECHOSO.
  // La redirección es solo informativa.
  const veredicto = verdictoMalicioso
    ? 'MALICIOSO'
    : (motoresMalicioso || descargaEjecutable || categorias.length > 0) ? 'SOSPECHOSO' : 'INCIERTO';

  return {
    disponible: true,
    veredicto,
    score,
    descargaEjecutable: Boolean(descargaEjecutable),
    indicadores,
    screenshotUrl: cargo ? (resultado.task?.screenshotURL ?? null) : null,
    capturaMotivo: descargas.length > 0 ? 'descarga_directa' : (cargo ? null : 'destino_inaccesible'),
    capturaDetalle: errorCarga ?? null,
  };
}

// VirusTotal v3
async function consultarReportePrevioVT(url, deadline) {
  const id = idVirusTotal(url);

  const resp = await fetchConTimeout(
    `https://www.virustotal.com/api/v3/urls/${id}`,
    { headers: { 'x-apikey': VT_API_KEY } },
    msRestantes(deadline)
  );

  if (resp.status === 404) {
    return null; // Realmente no existe un reporte previo
  }

  if (!resp.ok) {
    const detalle = await resp.text();
    console.error('VT report error', {
      status: resp.status,
      detalle: detalle.slice(0, 300)
    });
    throw new Error(`VirusTotal report falló: ${resp.status}`);
  }

  return await resp.json();
}

async function enviarAVirusTotal(url, deadline) {
  const resp = await fetchConTimeout('https://www.virustotal.com/api/v3/urls', {
    method: 'POST',
    headers: { 'x-apikey': VT_API_KEY, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `url=${encodeURIComponent(url)}`,
  }, msRestantes(deadline));
  if (!resp.ok) {
    throw new Error(`VirusTotal submit falló: ${resp.status}`);
  }
  const data = await resp.json();
  return data.data.id; // analysis id
}

async function consultarAnalisisVT(analysisId, deadline) {
  while (Date.now() < deadline) {
    const timeoutFetch = msRestantes(deadline);
    if (timeoutFetch <= 0) break;

    try {
      const resp = await fetchConTimeout(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { 'x-apikey': VT_API_KEY },
      }, timeoutFetch);
      if (resp.ok) {
      const data = await resp.json();
        if (data.data.attributes.status === 'completed') return data.data.attributes;
      }
    } catch (err) {
      console.warn(`VirusTotal poll falló analysis=${analysisId}: ${err.name}`);
    }

    const restante = deadline - Date.now();
    if (restante <= 0) break;
    await esperar(Math.min(VT_POLL_INTERVAL_MS, restante));
  }
  return null;
}

async function obtenerDatosVirusTotal(url, deadline) {
  const previo = await consultarReportePrevioVT(url, deadline);
  if (previo) return previo.data.attributes.last_analysis_stats ?? null;
  if (Date.now() >= deadline) return null;
  const analysisId = await enviarAVirusTotal(url, deadline);
  const resultado = await consultarAnalisisVT(analysisId, deadline);
  return resultado?.stats ?? null;
}

function extraerIndicadoresVirusTotal(stats) {
  if (!stats) {
    return { disponible: false, indicadores: [] };
  }
  const indicadores = [];
  if (stats.malicious > 0) {
    indicadores.push({
      indicador: 'virustotal_motores_maliciosos',
      detalle: `${stats.malicious} motores lo marcan como malicioso`,
    });
  }
  if (stats.suspicious > 0) {
    indicadores.push({
      indicador: 'virustotal_motores_sospechosos',
      detalle: `${stats.suspicious} motores lo marcan como sospechoso`,
    });
  }
  return {
    disponible: true,
    veredicto: stats.malicious > UMBRAL_VT_MALICIOSO ? 'MALICIOSO' : (stats.malicious > 0 ? 'SOSPECHOSO' : 'INCIERTO'),
    stats,
    indicadores,
  };
}

// Orquestación
/**
 * Ejecuta URLScan.io y VirusTotal en paralelo con degradación progresiva.
 * Si una fuente falla o no responde a tiempo, se ignora y se decide con
 * la que sí respondió. Si ninguna respondió, veredicto queda PENDIENTE.
 */
export async function analizarSandbox(url, deadline) {
  let uuidUrlscan = null; // se conserva aunque el polling falle o dé timeout
  const [urlscanResultado, vtStats] = await Promise.allSettled([
    (async () => {
      const { uuid } = await enviarAUrlscan(url, deadline);
      uuidUrlscan = uuid;
      console.log(`URLScan submit OK, uuid=${uuid}`);
      try {
        return await consultarUrlscan(uuid, deadline);
      } catch (err) {
        console.warn(`URLScan polling falló uuid=${uuid}: ${err.name}`);
        return { _error: 'sin_respuesta_a_tiempo' };
      }
    })(),
    obtenerDatosVirusTotal(url, deadline),
  ]);

  if (urlscanResultado.status === 'rejected') {
    console.error('URLScan falló:', urlscanResultado.reason);
  }
  if (vtStats.status === 'rejected') {
    console.error('VirusTotal falló:', vtStats.reason);
  }

  const urlscan = extraerIndicadoresUrlscan(
    urlscanResultado.status === 'fulfilled' ? urlscanResultado.value : null
  );
  const virustotal = extraerIndicadoresVirusTotal(
    vtStats.status === 'fulfilled' ? vtStats.value : null
  );

  const indicadoresTotales = [...urlscan.indicadores, ...virustotal.indicadores];
  const niveles = [urlscan.veredicto, virustotal.veredicto];
  const veredictoSandbox = niveles.includes('MALICIOSO') ? 'MALICIOSO'
    : niveles.includes('SOSPECHOSO') ? 'SOSPECHOSO' : 'PENDIENTE';

  let capturaMotivo = null, capturaDetalle = null;
  if (!urlscan.screenshotUrl) {
    if (urlscanResultado.status === 'rejected') {
      const razon = urlscanResultado.reason;
      if (esErrorDeTiempo(razon)) {
        capturaMotivo = 'urlscan_envio_timeout';
      } else {
        capturaMotivo = 'urlscan_envio_rechazado';
        capturaDetalle = `HTTP ${razon?.status ?? '?'}: ${razon?.detalle ?? razon?.message}`;
      }
    } else if (urlscanResultado.value?._eliminado) {
      capturaMotivo = 'urlscan_scan_eliminado';
    } else {
      capturaMotivo = urlscan.capturaMotivo ?? 'sin_captura';
      capturaDetalle = urlscan.capturaDetalle ?? null;
    }
    console.warn(JSON.stringify({ evento: 'captura_no_disponible', url, motivo: capturaMotivo, detalle: capturaDetalle }));
  }

  return {
    veredicto: veredictoSandbox, // ninguna fuente concluyente -> pasa a F2.3 (evidencia visual, no veredicto)
    indicadores: indicadoresTotales,
    uuid: uuidUrlscan,
    descargaEjecutable: urlscan.descargaEjecutable ?? false,
    screenshotUrl: urlscan.screenshotUrl ?? null,
    captura: { disponible: Boolean(urlscan.screenshotUrl), motivo: capturaMotivo, detalle: capturaDetalle },
    fuentes: {
      urlscan: { disponible: urlscan.disponible, veredicto: urlscan.veredicto ?? null },
      virustotal: { disponible: virustotal.disponible, veredicto: virustotal.veredicto ?? null },
    },
  };
}
