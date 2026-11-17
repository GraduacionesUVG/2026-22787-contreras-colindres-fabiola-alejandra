/**
 * Normalización y parsing de URL (S5, RFC 3986)
 * Produce una representación consistente de la URL antes de que
 * cualquier filtro (F2.1 en adelante) la analice.
 */

/**
 * Normaliza una URL: decodifica percent-encoding, fuerza minúsculas en el host,
 * quita puertos por defecto y trailing slash redundante.
 * Lanza error si la URL es inválida o no usa http/https (fuera de alcance del proyecto).
 */
export function normalizarURL(urlOriginal) {
  let parsed;
  try {
    parsed = new URL(urlOriginal);
  } catch (err) {
    throw new Error('URL_MALFORMADA');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('ESQUEMA_NO_SOPORTADO');
  }

  // Host siempre en minúsculas (ej. Ejemplo.com y ejemplo.com son el mismo dominio)
  const host = parsed.hostname.toLowerCase();

  // Decodificar percent-encoding en el path y query para exponer patrones ocultos
  let path = decodeSeguro(parsed.pathname);
  const query = decodeSeguro(parsed.search);

  // Quitar trailing slash redundante, excepto si el path es solo "/"
  if (path.length > 1 && path.endsWith('/')) {
    path = path.slice(0, -1);
  }

  // Reconstruir con el puerto solo si no es el puerto por defecto del esquema
  const puertoDefault = parsed.protocol === 'https:' ? '443' : '80';
  const puerto = parsed.port && parsed.port !== puertoDefault ? `:${parsed.port}` : '';

  const urlNormalizada = `${parsed.protocol}//${host}${puerto}${path}${query}`;

  return {
    urlOriginal,
    urlNormalizada,
    dominio: host,
    protocolo: parsed.protocol.replace(':', ''),
    path,
    query,
  };
}

// decodeURIComponent lanza excepción con secuencias % mal formadas;
// se captura para no tumbar el análisis completo por una URL ofuscada de forma inválida.
function decodeSeguro(componente) {
  try {
    return decodeURIComponent(componente);
  } catch {
    return componente;
  }
}
