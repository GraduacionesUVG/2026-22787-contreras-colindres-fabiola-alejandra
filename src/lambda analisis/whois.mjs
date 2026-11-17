/**
 * Consulta de antigüedad de dominio — Filtro F2.1
 * Usa WhoisJSON API (whoisjson.com) con caché en DynamoDB (TTL 7 días)
 * para no gastar cuota en dominios ya consultados recientemente.
 *
 * Migrado desde WhoisXML API (S8) por agotamiento de cuota gratuita.
 * Cambio respecto al protocolo, que cita "WhoisXML API" explícitamente
 * en OE5 y en Recursos Tecnológicos
 *
 * Estrategia de degradación progresiva: si la API externa falla o
 * excede el timeout, se devuelve null en vez de tumbar el análisis
 * completo — el score heurístico simplemente no suma el criterio
 * de antigüedad de dominio para esa consulta. Esta función NUNCA lanza.
 */
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';

const TTL_SEGUNDOS = 7 * 24 * 60 * 60; // 7 días
const TIMEOUT_MS = 3000; // según métrica: p90 <= 3s
const REGEX_IP = /^(\d{1,3}\.){3}\d{1,3}$/;

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);

/**
 * Devuelve { antiguedadDias, fechaCreacion, desdeCache } o null si no
 * se pudo obtener el dato (dominio inválido, no encontrado, timeout, error de API).
 */
export async function obtenerAntiguedadDominio(dominio) {
  try {
    if (typeof dominio !== 'string' || !dominio || REGEX_IP.test(dominio)) {
      console.warn('Dominio inválido o IP literal, se omite consulta WHOIS:', dominio);
      return null;
    }

    const cacheado = await leerCache(dominio);
    if (cacheado) {
      return { ...cacheado, desdeCache: true };
    }

    const resultado = await consultarWhoisJSON(dominio);
    if (resultado) {
      await guardarCache(dominio, resultado);
      return { ...resultado, desdeCache: false };
    }

    return null;
  } catch (err) {
    console.error('Error inesperado en obtenerAntiguedadDominio:', err);
    return null;
  }
}

async function leerCache(dominio) {
  try {
    const { Item } = await docClient.send(
      new GetCommand({
        TableName: process.env.WHOIS_CACHE_TABLE,
        Key: { domain: dominio },
      })
    );
    if (!Item) return null;

    const ahoraEpoch = Math.floor(Date.now() / 1000);
    if (Item.ttl && Item.ttl < ahoraEpoch) return null;

    return { antiguedadDias: Item.antiguedadDias, fechaCreacion: Item.fechaCreacion };
  } catch (err) {
    console.error('Error leyendo caché WHOIS:', err);
    return null;
  }
}

async function guardarCache(dominio, resultado) {
  try {
    const ttl = Math.floor(Date.now() / 1000) + TTL_SEGUNDOS;
    await docClient.send(
      new PutCommand({
        TableName: process.env.WHOIS_CACHE_TABLE,
        Item: {
          domain: dominio,
          antiguedadDias: resultado.antiguedadDias,
          fechaCreacion: resultado.fechaCreacion,
          ttl,
        },
      })
    );
  } catch (err) {
    console.error('Error guardando caché WHOIS:', err);
  }
}

async function consultarWhoisJSON(dominio) {
  const url = `https://whoisjson.com/api/v1/whois?domain=${encodeURIComponent(dominio)}`;

  try {
    const res = await fetch(url, {
      headers: { Authorization: `TOKEN=${process.env.WHOIS_API_KEY}` },
      signal: AbortSignal.timeout(TIMEOUT_MS), // cubre también la lectura del body
    });

    if (!res.ok) {
      // Leemos el cuerpo para saber el motivo real del error
      const cuerpo = await res.text().catch(() => '');

      if (res.status === 400) {
        // Petición inválida: dominio mal formado o TLD no soportado.
        // No es reintentable ni indica falla del proveedor.
        console.warn(`WhoisJSON 400 (solicitud inválida) para ${dominio}:`, cuerpo.slice(0, 300));
      } else if (res.status === 401 || res.status === 403) {
        console.error('WhoisJSON: API key inválida o sin permisos:', res.status);
      } else if (res.status === 429) {
        console.error('WhoisJSON: cuota o límite de tasa agotado (429)');
      } else {
        console.error(`WhoisJSON error HTTP ${res.status} para ${dominio}:`, cuerpo.slice(0, 300));
      }
      return null; // degradación progresiva: el análisis continúa sin este criterio
    }

    const data = await res.json();

    // Dominio no registrado (disponible para compra): no hay fecha de
    // creación que evaluar — no es el caso que el criterio busca detectar.
    if (data.registered === false) return null;

    const fechaCreacion = data.created;
    if (!fechaCreacion) return null; // dato no disponible para este TLD/registro

    const fechaMs = new Date(fechaCreacion).getTime();
    if (Number.isNaN(fechaMs)) {
      console.warn(`WhoisJSON devolvió fecha inválida para ${dominio}:`, fechaCreacion);
      return null;
    }

    const antiguedadDias = Math.floor((Date.now() - fechaMs) / (1000 * 60 * 60 * 24));

    console.log(`WhoisJSON OK para ${dominio}: ${antiguedadDias} días`);
    return { antiguedadDias, fechaCreacion };
  } catch (err) {
    console.error('Error consultando WhoisJSON:', err.name, err.message);
    return null;
  }
}
