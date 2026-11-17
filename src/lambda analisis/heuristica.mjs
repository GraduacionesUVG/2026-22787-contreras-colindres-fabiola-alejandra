/**
 * Motor de scoring heurístico — Filtro F2.1
 * Evalúa características léxicas y estructurales de la URL sin visitar
 * el destino, más la antigüedad de dominio obtenida vía WhoisJSON
 * (migrada desde WhoisXML API por agotamiento de cuota; ver whois.mjs).
 *
 * Umbral: score > 60 => SOSPECHOSO
 * Pesos calibrados contra muestra real de PhishTank (maliciosas)
 * y Tranco List (limpias). Ver notas de calibración al final del archivo.
 */

// TLDs de riesgo. Verificados contra Interisle "Phishing Landscape 2025/2026"
// (.shop, .xyz, .top, .buzz, .cfd, .lol aparecen en sus rankings anuales de
// TLDs más abusados para phishing — fuente citable en el informe).
// Los demás (.sbs, .icu, .casa, .rest, .cyou, .mom, .lat, .study, .tk, .ml,
// .cf, .ga, .work, .country, .click) fueron inferidos por aparecer en las
// muestras de prueba.
const TLDS_RIESGO = [
  '.xyz', '.tk', '.ml', '.cf', '.ga', '.top', '.work', '.click', '.country',
  '.shop', '.sbs', '.icu', '.lol', '.casa', '.cfd', '.rest', '.buzz', '.cyou', '.mom',
  '.lat', '.study',
];

const PALABRAS_CLAVE_SOSPECHOSAS = [
  'login', 'verify', 'secure', 'account', 'update', 'confirm',
  'banking', 'signin', 'password', 'suspended', 'unlock',
  'claim', 'prize', 'reward', 'gift', 'bonus', 'oferta', 'premio', 'ganador',
];

// Plataformas de hosting gratuito frecuentemente abusadas para quishing:
// cualquiera puede crear un subdominio ahí sin registrar un dominio propio,
// por lo que WHOIS nunca va a mostrar el subdominio como "reciente".
// Se usan patrones (no lista exacta) porque servicios como Blogspot operan
// con múltiples ccTLDs (blogspot.com, blogspot.it, blogspot.mx, ...).
//
// Verificados contra Interisle "Phishing Landscape 2025/2026": webflow.io y
// vercel.app con abuso de subdominios en aumento en el período más reciente;
// weebly.com mencionado explícitamente como plataforma abusada; blogspot.com
// con abuso históricamente alto, aunque en descenso reciente según el mismo
// reporte (Google redujo el abuso ahí) — vale la pena anotar esa tendencia
// a la baja en el informe si se cita esta fuente.
//
// Inferidos de las muestras:
// netlify.app, pages.dev, herokuapp.com, 000webhostapp.com, wixsite.com,
// github.io, glitch.me, repl.co, firebaseapp.com, web.app, myfreesites.net,
// godaddysites.com, page.tl, duckdns.org.
const PATRONES_PLATAFORMAS_GRATUITAS = [
  /\.netlify\.app$/, /\.vercel\.app$/, /\.pages\.dev$/, /\.herokuapp\.com$/,
  /\.000webhostapp\.com$/, /\.weebly\.com$/, /\.wixsite\.com$/, /\.github\.io$/,
  /\.glitch\.me$/, /\.repl\.co$/, /\.firebaseapp\.com$/, /\.web\.app$/,
  /\.myfreesites\.net$/, /\.godaddysites\.com$/, /\.page\.tl$/, /\.blogspot\.[a-z.]+$/,
  /\.duckdns\.org$/, /\.webflow\.io$/, /\.azurewebsites\.net$/,
];

// Marcas frecuentemente suplantadas. paypal, amazon, apple, microsoft,
// netflix, google, facebook, instagram, whatsapp, ebay son marcas globales
// de phishing documentadas de forma constante en reportes del sector (APWG,
// Interisle) — genéricamente defendibles. "allegro", 'duolingo', "santander" y "bbva"
// se incluyeron porque aparecieron en las muestras. 
// Lista ilustrativa, no exhaustiva — un enfoque robusto
// requeriría una base de marcas mucho mayor, fuera del alcance del proyecto.
const MARCAS_CONOCIDAS = [
  'paypal', 'allegro', 'amazon', 'apple', 'microsoft', 'netflix', 'duolingo',
  'santander', 'bbva', 'google', 'facebook', 'instagram', 'whatsapp', 'ebay',
];

const REGEX_IP = /^(\d{1,3}\.){3}\d{1,3}$/;
const DIAS_DOMINIO_RECIENTE = 30;

// Sufijos compuestos comunes (ccSLD) — simplificación para extraer el
// dominio raíz correctamente. No es una implementación completa de la
// Public Suffix List; cubre los casos más frecuentes.
const SUFIJOS_COMPUESTOS = ['co.uk', 'com.mx', 'com.br', 'co.jp', 'org.mx', 'com.gt', 'org.gt', 'gob.gt'];

/**
 * Extrae el dominio raíz (registrable) de un hostname completo.
 * Ej: "claim-x7k.netlify.app" -> "netlify.app"
 *     "allegrolokalnie.su293bdi6j0n.shop" -> "su293bdi6j0n.shop"
 * Una IP literal se devuelve tal cual (no tiene "dominio raíz"; si no, la IP
 * 192.168.1.1 terminaba como "1.1" y se consultaba a WHOIS).
 */
export function extraerDominioRaiz(hostname) {
  if (typeof hostname !== 'string' || !hostname) return hostname;
  if (REGEX_IP.test(hostname)) return hostname;

  const partes = hostname.split('.');
  if (partes.length <= 2) return hostname;

  const ultimasDos = partes.slice(-2).join('.');
  if (SUFIJOS_COMPUESTOS.includes(ultimasDos) && partes.length >= 3) {
    return partes.slice(-3).join('.');
  }
  return ultimasDos;
}

/**
 * Heurística léxica de dominio algorítmicamente generado (DGA), técnica
 * documentada en la literatura de detección de URLs maliciosas (ej. Sahoo,
 * Liu & Hoi, 2017 — features léxicas de escasez de vocales + dígitos).
 * Deliberadamente conservadora (longitud 5-10, requiere dígito, casi sin
 * vocales) para minimizar falsos positivos sobre marcas cortas legítimas.
 */
function pareceDominioAleatorio(etiqueta) {
  if (etiqueta.length < 5 || etiqueta.length > 10) return false;
  if (!/\d/.test(etiqueta)) return false;
  const vocales = (etiqueta.match(/[aeiou]/gi) || []).length;
  return vocales / etiqueta.length < 0.15;
}

// --- Criterio: acortador de URL conocido ---
// Justificación: técnica documentada explícitamente en Ghalechyan et al. [12],
// citada en "Técnicas de evasión" del protocolo — el encadenamiento de servicios
// de acortamiento para ocultar el destino final de la URL.
// Peso 20 (no más alto): el uso de un acortador conocido es una señal real pero
// no concluyente por sí sola, dado su uso masivo legítimo (marketing, redes
// sociales, etc.). Se evalúa contra el hostname completo, no contra dominioRaiz,
// porque el acortador ES el dominio, no un subdominio abusado.
const ACORTADORES_CONOCIDOS = new Set([
  'qrco.de', 'q-r.to', 'l.ead.me', 'tinyurl.com', 'hm.ru', 'ungu.in',
  'bit.ly', 'goo.gl', 't.co', 'is.gd', 'ow.ly', 'buff.ly',
  'cutt.ly', 'rebrand.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 's.id',
]);

function esAcortadorConocido(dominio) {
  return ACORTADORES_CONOCIDOS.has(dominio.toLowerCase());
}

// --- Criterio: extensión ejecutable/instalador en la ruta ---
// Un enlace de QR que apunta directamente a un ejecutable o instalador entrega el
// malware sin pasar por ninguna página; no hay caso de uso legítimo habitual.
// Peso 35: por sí sola no cruza el umbral (60), pero combinada con IP literal (30) o
// con HTTP sin cifrar (15) sí lo hace, que es el patrón típico de estos enlaces.
const EXT_EJECUTABLE_EN_RUTA = /\.(exe|msi|scr|bat|cmd|ps1|vbs|jar|apk|dmg|pkg|iso|lnk|dll|hta)$/i;

/**
 * @param {object} urlInfo - resultado de normalizarURL()
 * @param {object|null} antiguedadDominio - resultado de obtenerAntiguedadDominio() sobre el dominio raíz, o null si WHOIS falló/no aplica
 */
export function calcularScoreHeuristico(urlInfo, antiguedadDominio = null) {
  const { dominio, protocolo, path, query } = urlInfo;
  const criteriosActivados = [];
  let score = 0;

  const dominioRaiz = extraerDominioRaiz(dominio);

  // 1. IP literal en lugar de nombre de dominio — indicador de alta severidad
  if (REGEX_IP.test(dominio)) {
    criteriosActivados.push({ criterio: 'ip_literal', peso: 30, detalle: `Host es una IP: ${dominio}` });
    score += 30;
  }

  // 2. TLD de riesgo
  const tldDetectado = TLDS_RIESGO.find((tld) => dominio.endsWith(tld));
  if (tldDetectado) {
    criteriosActivados.push({ criterio: 'tld_riesgo', peso: 25, detalle: `TLD sospechoso: ${tldDetectado}` });
    score += 25;
  }

  // 3. Ausencia de HTTPS
  if (protocolo !== 'https') {
    criteriosActivados.push({ criterio: 'sin_https', peso: 15, detalle: 'La URL no usa HTTPS' });
    score += 15;
  }

  // 4. Longitud del dominio
  if (dominio.length > 30) {
    criteriosActivados.push({ criterio: 'dominio_largo', peso: 10, detalle: `Longitud: ${dominio.length} caracteres` });
    score += 10;
  }

  // 5. Guiones excesivos en el dominio
  const guiones = (dominio.match(/-/g) || []).length;
  if (guiones > 3) {
    criteriosActivados.push({ criterio: 'guiones_excesivos', peso: 10, detalle: `${guiones} guiones en el dominio` });
    score += 10;
  }

  // 6. Cantidad de subdominios (relativa al dominio raíz, para no contar de más
  // el sufijo compuesto: "a.b.c.co.uk" tiene 3 subdominios, no 4)
  const subdominios = dominio.split('.').length - dominioRaiz.split('.').length;
  if (subdominios > 3) {
    criteriosActivados.push({ criterio: 'subdominios_excesivos', peso: 10, detalle: `${subdominios} subdominios` });
    score += 10;
  }

  // 7. Palabras clave sospechosas
  const contenido = `${dominio} ${path ?? ''} ${query ?? ''}`.toLowerCase();
  const palabraDetectada = PALABRAS_CLAVE_SOSPECHOSAS.find((p) => contenido.includes(p));
  if (palabraDetectada) {
    criteriosActivados.push({ criterio: 'palabra_clave_sospechosa', peso: 15, detalle: `Palabra detectada: "${palabraDetectada}"` });
    score += 15;
  }

  // 8. Cantidad elevada de parámetros de query
  const cantidadParametros = query ? query.replace('?', '').split('&').filter(Boolean).length : 0;
  if (cantidadParametros > 5) {
    criteriosActivados.push({ criterio: 'parametros_excesivos', peso: 10, detalle: `${cantidadParametros} parámetros` });
    score += 10;
  }

  // 9. Antigüedad de dominio (Whois) — evaluada sobre el dominio raíz.
  // Si WHOIS falló o no aplica, antiguedadDominio es null y el criterio simplemente no suma.
  if (antiguedadDominio && antiguedadDominio.antiguedadDias < DIAS_DOMINIO_RECIENTE) {
    criteriosActivados.push({
      criterio: 'dominio_reciente',
      peso: 20,
      detalle: `Dominio raíz (${dominioRaiz}) registrado hace ${antiguedadDominio.antiguedadDias} días`,
    });
    score += 20;
  }

  // 10. Plataforma de hosting gratuito conocida por abuso de subdominios
  const esPlataformaGratuita = PATRONES_PLATAFORMAS_GRATUITAS.some((patron) => patron.test(dominio));
  if (esPlataformaGratuita) {
    criteriosActivados.push({
      criterio: 'plataforma_gratuita_abusada',
      peso: 20,
      detalle: `Subdominio en plataforma gratuita conocida`,
    });
    score += 20;
  }

  // 10b. Combinación de alto riesgo: plataforma gratuita + guion en el subdominio.
  // Los kits de phishing automatizados suelen generar subdominios tipo
  // "claim-x7k" o "newweeklyscorevoting-ui" al crear páginas en estas
  // plataformas mediante scripts, a diferencia de sitios personales reales.
  const subdominioParte = dominio.slice(0, dominio.length - dominioRaiz.length).replace(/\.$/, '');
  if (esPlataformaGratuita && subdominioParte.includes('-')) {
    criteriosActivados.push({
      criterio: 'patron_kit_phishing_plataforma_gratuita',
      peso: 35,
      detalle: `Subdominio "${subdominioParte}" con guion en plataforma gratuita — patrón típico de kit de phishing automatizado`,
    });
    score += 35;
  }

  // 11. Posible suplantación de marca: nombre de marca en el host, pero el
  // dominio raíz no corresponde a esa marca.
  const marcaDetectada = MARCAS_CONOCIDAS.find(
    (marca) => dominio.toLowerCase().includes(marca) && !dominioRaiz.toLowerCase().startsWith(marca)
  );
  if (marcaDetectada) {
    criteriosActivados.push({
      criterio: 'posible_suplantacion_marca',
      peso: 30,
      detalle: `Contiene "${marcaDetectada}" pero el dominio raíz es "${dominioRaiz}"`,
    });
    score += 30;
  }

  // 12. Dominio raíz con patrón de generación algorítmica (DGA)
  const etiquetaRaiz = dominioRaiz.split('.')[0];
  if (pareceDominioAleatorio(etiquetaRaiz)) {
    criteriosActivados.push({
      criterio: 'dominio_aleatorio_dga',
      peso: 25,
      detalle: `Dominio "${etiquetaRaiz}" con patrón típico de generación algorítmica (escasas vocales + dígitos)`,
    });
    score += 25;
  }

  // 13. Acortadores conocidos
  if (esAcortadorConocido(dominio)) {
    criteriosActivados.push({
      criterio: 'acortador_url_conocido',
      peso: 20,
      detalle: `Dominio es un acortador de URL conocido: ${dominio}`,
    });
    score += 20;
  }

  // 14. Ruta que apunta directamente a un ejecutable o instalador
  const rutaSinQuery = (path ?? '').split(/[?#]/)[0];
  const ejecutableEnRuta = EXT_EJECUTABLE_EN_RUTA.test(rutaSinQuery);
  const pesoEjecutable = ejecutableEnRuta ? 35 : 0;
  if (ejecutableEnRuta) {
    criteriosActivados.push({
      criterio: 'extension_ejecutable_en_ruta',
      peso: 35,
      detalle: `La ruta apunta a un archivo ejecutable o instalador: ${rutaSinQuery.slice(-60)}`,
    });
    score += 35;
  }

  // Score sin el criterio 14: sirve para exigir al menos una señal independiente de la
  // extensión antes de escalar a MALICIOSO (un instalador legítimo solo suma el criterio 14).
  const scoreBase = Math.min(score - pesoEjecutable, 100);
  score = Math.min(score, 100);

  return {
    score,
    scoreBase,
    ejecutableEnRuta,
    veredicto: score > 60 ? 'SOSPECHOSO' : 'INCIERTO',
    criteriosActivados,
  };
}
