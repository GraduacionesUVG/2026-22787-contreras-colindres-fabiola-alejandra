/**
 * Muestra lo que URLScan.io registró de una página, sin pasar por la cascada.
 * Sirve para ver la forma real de page.redirected y data.redirects con una redirección
 * verdadera (caso C1) y para saber qué comportamiento queda registrado en C2 a C4.
 *
 * Uso: node inspeccionar-urlscan.mjs <url>      (requiere la variable URLSCAN_API_KEY)
 */
const key = process.env.URLSCAN_API_KEY;
const url = process.argv[2];
if (!key || !url) {
  console.error('Uso: URLSCAN_API_KEY definida y node inspeccionar-urlscan.mjs <url>');
  process.exit(1);
}

const sub = await fetch('https://urlscan.io/api/v1/scan/', {
  method: 'POST',
  headers: { 'API-Key': key, 'Content-Type': 'application/json' },
  body: JSON.stringify({ url, visibility: 'unlisted' }),
});
const subData = await sub.json();

if (!sub.ok) {
  console.log(`El envío falló (HTTP ${sub.status}):`, subData);
} else {
  console.log(`Scan enviado, uuid=${subData.uuid}. Esperando el resultado...`);
  const inicio = Date.now()
  const limite = inicio + 90000;
  let r = null;
  while (!r && Date.now() < limite) {
    await new Promise((res) => setTimeout(res, 4000));
    const resp = await fetch(`https://urlscan.io/api/v1/result/${subData.uuid}/`, { headers: { 'API-Key': key } });
    if (resp.status === 200) r = await resp.json();
    else if (resp.status !== 404) {
      console.log(`Estado inesperado: HTTP ${resp.status}`);
      break;
    }
  }
  if (r) {
    console.log(r, '\n\n')
    const fin = Date.now()
    console.log('\ntiempo de ejecucion: ', (fin - inicio), '\n')
    console.log('\npage:', JSON.stringify(r.page, null, 2));
    console.log('\ndata.redirects:', JSON.stringify(r.data?.redirects, null, 2));
    console.log('\ndownloads: ', JSON.stringify(r.meta.processors.download.data, null, 2))
    console.log('\nverdicts.overall:', JSON.stringify(r.verdicts?.overall, null, 2));
    console.log('\nSolicitudes registradas:', r.data?.requests?.length ?? 'n/a');
    console.log('Dominios contactados:', r.lists?.domains);
  } else {
    console.log('No hubo resultado dentro de 90 s.');
  }
}
