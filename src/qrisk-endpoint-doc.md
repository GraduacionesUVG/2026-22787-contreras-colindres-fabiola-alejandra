# QRisk — Documentación de Endpoints (Backend)

Estado actual: **F1 (integración) + F2.1 + F2.2 + F2.3 implementados. Endpoint de reportes implementado (S11).**

---

## `POST /analyze`

```
POST https://<tu-invoke-url>/dev/analyze
Content-Type: application/json
```

⚠️ **Timing:** cuando F1 y F2.1 no son concluyentes, el request puede tardar **varios
segundos hasta ~35s en el caso típico** (F2.2 hace polling contra URLScan.io y
VirusTotal en paralelo, con presupuesto de tiempo compartido). En el peor caso
(proveedores lentos o colgados) el backend se corta solo a los **~90s** y responde
con lo que tenga hasta ese momento (ver [Degradación progresiva](#degradación-progresiva)).
Configura el timeout de red del cliente HTTP en **al menos 90-95s** para esta ruta
específica; si el cliente corta antes, perderá la respuesta aunque el backend la haya
calculado bien.

### Request Body

| Campo           | Tipo   | Requerido | Descripción                                                                                                                                                            |
| --------------- | ------ | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `url`         | string | Sí       | La URL extraída del código QR.                                                                                                                                        |
| `resultadoF1` | string | No        | Veredicto del Filtro F1 (blacklists). Valores válidos: `"SEGURO"`, `"MALICIOSO"`, `"INCIERTO"`. Si se omite o viene un valor inválido, se asume `"INCIERTO"`. |

**Ejemplo:**

```json
{
  "url": "https://ejemplo.com",
  "resultadoF1": "INCIERTO"
}
```

### Cómo funciona la cascada (por dentro)

1. Se valida que `url` exista y sea un string → si no, `400`.
2. Se normaliza la URL (RFC 3986).
3. Si `resultadoF1` es `SEGURO` o `MALICIOSO` → **corte anticipado**, ese es el veredicto final.
4. Si `resultadoF1` es `INCIERTO` → se busca si ya existe un análisis reciente para
   esa misma URL. **Solo se cachean los veredictos `SOSPECHOSO` / `MALICIOSO`
   (TTL de 7 días)**; `PENDIENTE` y `SEGURO` no se cachean, así que esas URLs se
   re-analizan en cada request. Si hay un análisis vigente, se devuelve directo
   (`desde_cache: true`), sin volver a correr el análisis. Si la base de datos no
   está disponible, simplemente se omite la caché y se continúa.
5. Si no hay caché vigente, corre el motor heurístico F2.1 (14 criterios, incluido
   uno que detecta rutas que apuntan directamente a un ejecutable o instalador,
   como `.exe`, `.apk` o `.msi`).
   Incluye la antigüedad del dominio raíz (WhoisJSON, con caché propia de 7 días);
   si esa consulta falla, el criterio simplemente no suma.
   - Score > 60 → veredicto `SOSPECHOSO`, corte anticipado. **Excepción:** si la ruta
     apunta a un ejecutable o instalador, no se corta: se sigue a F2.2 para confirmar
     si realmente hay una descarga. Si F2.2 no confirma nada o no responde, queda
     `SOSPECHOSO` por F2.1.
   - Score ≤ 60 → **corre F2.2**.
6. F2.2 consulta URLScan.io y VirusTotal en paralelo, con degradación progresiva.
   - **`MALICIOSO`** (confirmado) si ocurre cualquiera de estas:
     - URLScan marca el sitio como malicioso (`urlscan_verdict_malicioso`).
     - VirusTotal reporta **más de 5** motores maliciosos (los "sospechosos" no cuentan
       para este umbral).
     - Hay una descarga ejecutable confirmada **y** el score heurístico base (sin contar
       el criterio de extensión ejecutable) es mayor que 30.
   - **`SOSPECHOSO`** si ocurre cualquiera de estas (y ninguna de las anteriores):
   - Si URLScan.io **elimina** el scan tras analizarlo (contenido confirmado como
     malicioso) → también cuenta como `SOSPECHOSO` (`urlscan_scan_eliminado`).
   - Si los motores de URLScan lo marcan como malicioso (`urlscan_motores_maliciosos`)
     → `SOSPECHOSO`, aunque el veredicto general de URLScan sea limpio.
   - Si URLScan asigna categorías de riesgo (`categorias_riesgo`, por ejemplo phishing
     o malware) → `SOSPECHOSO`.
   - Si VirusTotal reporta entre 1 y 5 motores maliciosos → `SOSPECHOSO`.
   - Son solo **informativos** (no cambian el veredicto): los motores "sospechosos" de
     VirusTotal y la redirección a otro dominio (`redireccion_detectada`).
   - El veredicto final es el más grave entre F2.2 y F2.1 (`MALICIOSO` > `SOSPECHOSO` >
     `PENDIENTE`).
   - Si el enlace **descarga un archivo ejecutable** (`descarga_automatica_detectada`:
     `.exe`, `.apk`, `.msi`, etc., o tipo MIME de ejecutable) → `SOSPECHOSO` por sí sola
     (pasa a `MALICIOSO` si además hay señales heurísticas, ver arriba). Una
     descarga de otro tipo (por ejemplo un PDF) se informa como indicador pero no
     cambia el veredicto. Cuando hay descarga no hay página que mostrar, así que no
     se genera `screenshot_url` (`captura_motivo: "descarga_directa"`).
   - Si ninguna fuente es concluyente → `PENDIENTE` y sigue a F2.3.
7. F2.3 corre cuando F2.2 dejó un origen de captura: sube el screenshot a S3 propio
   y devuelve una URL firmada de 1h. F2.3 reintenta bajar el screenshot directamente. 
   Si falla, se degrada sin screenshot.

### Degradación progresiva

Ningún proveedor externo puede tumbar el análisis. Si algo falla o no responde a
tiempo, ese resultado simplemente **no aparece** y el veredicto se apoya en lo que
sí respondió (como mínimo, el score heurístico de F2.1).

| Qué falla                          | Efecto en la respuesta                                                                                               |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| WHOIS (error, cuota, timeout de 3s) | El score no suma `dominio_reciente`. La respuesta es normal.                                                       |
| URLScan.io                          | `fuentes_f2_2.urlscan: false`; sin sus indicadores. Normalmente sin `screenshot_url` (ver `captura_motivo`).   |
| VirusTotal                          | `fuentes_f2_2.virustotal: false`; sin sus indicadores.                                                             |
| URLScan.io **y** VirusTotal   | `PENDIENTE`, **sin** el campo `indicadores_f2_2`, `f2_2_completo: false` y un `mensaje` que lo indica. |
| Plazo total agotado                 | Igual que lo anterior para lo que no alcanzó a responder; el heurístico F2.1 siempre está presente.               |
| Captura de pantalla (F2.3 / S3)     | Sin `screenshot_url`; el veredicto no cambia.                                                                      |
| Base de datos (RDS)                 | Se omiten la caché y el guardado del análisis. El veredicto se devuelve igual.                                     |

> **Importante para la UI:** `indicadores_f2_2: []` significa "se analizó y no se
> encontró nada", mientras que la **ausencia** del campo significa "F2.2 no obtuvo
> datos". No muestres como "limpio" lo que simplemente no se pudo consultar. Para
> saber qué proveedores aportaron datos, usa `fuentes_f2_2`.

### Respuestas

**200 — Corte por F1:**

```json
{
  "url": "https://ejemplo.com",
  "dominio": "ejemplo.com",
  "veredicto_final": "MALICIOSO",
  "filtro_decisivo": "F1"
}
```

**200 — Resuelto por F2.1 (score > 60):**

```json
{
  "url": "http://mi-banco-verificacion.xyz/login?token=abc",
  "dominio": "mi-banco-verificacion.xyz",
  "veredicto_final": "SOSPECHOSO",
  "filtro_decisivo": "F2.1",
  "score_heuristico": 70,
  "criterios_f2_1": [
    { "criterio": "tld_riesgo", "peso": 25, "detalle": "TLD sospechoso: .xyz" }
  ]
}
```

**200 — Resuelto por F2.2, con vista previa:**

```json
{
  "url": "https://tinyurl.com/2p8x9k3j",
  "dominio": "tinyurl.com",
  "veredicto_final": "SOSPECHOSO",
  "filtro_decisivo": "F2.2",
  "score_heuristico": 20,
  "criterios_f2_1": [
    { "criterio": "acortador_url_conocido", "peso": 20, "detalle": "Dominio es un acortador de URL conocido: tinyurl.com" }
  ],
  "indicadores_f2_2": [
    { "indicador": "virustotal_motores_maliciosos", "detalle": "2 motores lo marcan como malicioso" }
  ],
  "fuentes_f2_2": { "urlscan": true, "virustotal": true },
  "f2_2_completo": true,
  "screenshot_url": "https://qrisk-screenshots-22787.s3.us-east-1.amazonaws.com/screenshots/<uuid>.png?X-Amz-...(firmada, expira en 1h)"
}
```

**200 — Resuelto por F2.2 como `MALICIOSO` (descarga de un ejecutable):**

```json
{
  "url": "http://191.44.66.129:8001/loader_classic.exe",
  "dominio": "191.44.66.129",
  "veredicto_final": "MALICIOSO",
  "filtro_decisivo": "F2.2",
  "score_heuristico": 80,
  "criterios_f2_1": [
    { "criterio": "ip_literal", "peso": 30, "detalle": "Host es una IP: 191.44.66.129" },
    { "criterio": "sin_https", "peso": 15, "detalle": "La URL no usa HTTPS" },
    { "criterio": "extension_ejecutable_en_ruta", "peso": 35, "detalle": "La ruta apunta a un archivo ejecutable o instalador: /loader_classic.exe" }
  ],
  "indicadores_f2_2": [
    { "indicador": "descarga_automatica_detectada", "detalle": "El enlace descarga un archivo: loader_classic.exe (PE32+ executable (console) x86-64, for MS Windows)" }
  ],
  "fuentes_f2_2": { "urlscan": true, "virustotal": true },
  "f2_2_completo": true,
  "captura_motivo": "descarga_directa"
}
```

Posibles valores de `indicadores_f2_2[].indicador`: `urlscan_verdict_malicioso`,
`urlscan_motores_maliciosos`, `urlscan_scan_eliminado`, `descarga_automatica_detectada`,
`redireccion_detectada`, `categorias_riesgo`, `virustotal_motores_maliciosos`,
`virustotal_motores_sospechosos`.

El `detalle` de `descarga_automatica_detectada` incluye nombres de archivo que vienen
del sitio analizado (contenido no confiable): el cliente debe mostrarlos como texto
plano, nunca interpretarlos como HTML.

`fuentes_f2_2` indica qué proveedor respondió (`true`) o no (`false`).
`f2_2_completo` es `true` solo si **ambos** respondieron. Estos dos campos aparecen
en toda respuesta que pasó por F2.2.

**200 — Resuelto desde caché (misma URL analizada recientemente):**

```json
{
  "url": "https://tinyurl.com/2p8x9k3j",
  "dominio": "tinyurl.com",
  "veredicto_final": "SOSPECHOSO",
  "filtro_decisivo": "F2.2",
  "score_heuristico": 20,
  "criterios_f2_1": [ { "criterio": "acortador_url_conocido", "peso": 20, "detalle": "..." } ],
  "indicadores_f2_2": [ { "indicador": "virustotal_motores_maliciosos", "detalle": "..." } ],
  "screenshot_url": "https://.../screenshots/<uuid>.png?...(URL firmada nueva, regenerada en cada respuesta)",
  "desde_cache": true
}
```

Útil para mostrar en la UI que el resultado ya se conocía, en vez de "analizando ahora".
Las respuestas desde caché no incluyen `fuentes_f2_2` ni `f2_2_completo` (no se
guardan). Como solo se cachean veredictos `SOSPECHOSO`/`MALICIOSO`, nunca verás
`PENDIENTE` con `desde_cache: true`.

**200 — Pendiente (F2.2 corrió y ninguna fuente fue concluyente):**

```json
{
  "url": "https://sitio-normal.com/pagina",
  "dominio": "sitio-normal.com",
  "veredicto_final": "PENDIENTE",
  "filtro_decisivo": null,
  "score_heuristico": 15,
  "criterios_f2_1": [],
  "indicadores_f2_2": [],
  "fuentes_f2_2": { "urlscan": true, "virustotal": true },
  "f2_2_completo": true,
  "mensaje": "F1, F2.1 y F2.2 no concluyentes"
}
```

**200 — Pendiente (F2.2 sin datos: timeout o proveedores caídos):**

```json
{
  "url": "https://sitio-normal.com/pagina",
  "dominio": "sitio-normal.com",
  "veredicto_final": "PENDIENTE",
  "filtro_decisivo": null,
  "score_heuristico": 15,
  "criterios_f2_1": [],
  "fuentes_f2_2": { "urlscan": false, "virustotal": false },
  "f2_2_completo": false,
  "mensaje": "F2.2 no disponible (timeout o proveedores caídos); resultado basado solo en F2.1",
  "captura_motivo": "urlscan_sin_respuesta_a_tiempo"
}
```

Fíjate en que aquí **no hay** `indicadores_f2_2`. Si solo falló uno de los dos
proveedores, el campo sí aparece (con los indicadores del que respondió) y
`fuentes_f2_2` marca cuál falló.

**Campos opcionales en las respuestas que pasaron por F2.2:**

- `screenshot_url`: puede aparecer tanto en `SOSPECHOSO` como en `PENDIENTE`, siempre
  que se haya podido generar la captura.
- `captura_motivo`: aparece cuando **no** hay `screenshot_url` y explica por qué
  (por ejemplo `urlscan_sin_respuesta_a_tiempo`, `urlscan_envio_rechazado`,
  `urlscan_scan_eliminado`, `destino_inaccesible`, `descarga_directa`, `sin_captura`). Es un texto de
  diagnóstico: no está pensado para mostrarse al usuario y su lista de valores
  puede crecer, así que no lo uses en lógica de negocio del cliente.

**400 / 500:**

```json
{ "error": "INVALID_INPUT", "message": "..." }
{ "error": "URL_INVALIDA", "message": "..." }
{ "error": "INTERNAL_ERROR", "message": "..." }
```

### Valores posibles

| `veredicto_final` | Significado                                                                                                                                                                        |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SEGURO`          | F1: whitelist / confiable.                                                                                                                                                         |
| `MALICIOSO`       | Confirmado: F1 (blacklist) o F2.2 (URLScan malicioso, más de 5 motores de VirusTotal, o descarga ejecutable con señales heurísticas). Usa `filtro_decisivo` para saber cuál. |
| `SOSPECHOSO`      | F2.1 (score > 60), o F2.2 (motores/categorías de URLScan, 1 a 5 motores de VirusTotal, scan eliminado o descarga ejecutable sola).                                                |
| `PENDIENTE`       | Ninguna capa concluyente. Incluye el caso en que F2.2 no obtuvo datos (ver `f2_2_completo` y `fuentes_f2_2` para distinguirlo).                                                |

`filtro_decisivo`: `"F1"`, `"F2.1"`, `"F2.2"`, o `null`.

> **Importante para la UI:** `MALICIOSO` ya no significa solo "está en una blacklist"; también puede venir de F2.2. Si necesitas distinguir el origen, usa `filtro_decisivo`.

---

## `POST /report` — nuevo (S11)

```
POST https://<tu-invoke-url>/dev/report
Content-Type: application/json
```

Guarda un reporte de QR/URL malicioso enviado por el usuario desde la pantalla de
resultado. Responde rápido (no depende de ninguna API externa).

⚠️ **Limitación conocida, para que la tengas presente si la UI la menciona:**
PhishTank no ofrece una API pública de envío de URLs (solo de consulta), así que
este endpoint **no reenvía automáticamente** el reporte a blacklists colaborativas
externas — lo guarda en nuestra propia base de datos como fuente de verdad interna.

### Request Body

| Campo           | Tipo    | Requerido | Descripción                                                                                                                                                                 |
| --------------- | ------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `url`         | string  | Sí       | La URL que se está reportando.                                                                                                                                              |
| `motivo`      | string  | No        | Texto libre del usuario explicando por qué la reporta.                                                                                                                      |
| `analisis_id` | integer | No        | El `id` del análisis previo de esta URL, si existe (para vincular el reporte al análisis original). Si se envía y no corresponde a un análisis real, responde `400`. |

**Ejemplo:**

```json
{
  "url": "https://ejemplo-malicioso.xyz",
  "motivo": "Formulario pidiendo credenciales bancarias"
}
```

### Respuestas

**200 — Reporte guardado:**

```json
{
  "reporte_id": 1,
  "url": "https://ejemplo-malicioso.xyz/",
  "recibido_en": "2026-09-30T00:15:45.478Z",
  "mensaje": "Reporte recibido. Gracias por ayudar a mejorar la detección."
}
```

**400 — Error de entrada:**

```json
{ "error": "INVALID_INPUT", "message": "El campo \"url\" es requerido y debe ser un string." }
```

```json
{ "error": "URL_INVALIDA", "message": "La URL no es válida o usa un esquema no soportado (solo http/https)." }
```

```json
{ "error": "ANALISIS_ID_INVALIDO", "message": "El \"analisis_id\" proporcionado no corresponde a ningún análisis existente." }
```

**500 — Error interno:**

```json
{ "error": "INTERNAL_ERROR", "message": "No se pudo guardar el reporte en este momento." }
```

---

## Ejemplos con curl

```bash
curl -X POST https://<tu-invoke-url>/dev/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://ejemplo.com", "resultadoF1": "INCIERTO"}'

curl -X POST https://<tu-invoke-url>/dev/report \
  -H "Content-Type: application/json" \
  -d '{"url": "https://ejemplo-malicioso.xyz", "motivo": "Formulario pidiendo credenciales"}'
```

Para forzar el camino hasta F2.2/F2.3 en `/analyze`, usa una URL con dominio de
acortador conocido (ej. `tinyurl.com/...`). Cada request que llega a F2.2 consume
cuota de URLScan.io y VirusTotal (planes gratuitos limitados), y los veredictos
`PENDIENTE` no se cachean, así que conviene no repetir la misma URL en pruebas
automatizadas.
