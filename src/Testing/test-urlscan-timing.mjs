const URLSCAN_API_KEY = process.env.URLSCAN_API_KEY;

const url = process.argv[2];

const t0 = Date.now();

const submitResp = await fetch('https://urlscan.io/api/v1/scan/', {
  method: 'POST',
  headers: {
    'API-Key': URLSCAN_API_KEY,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ url, visibility: 'unlisted' }),
});

const submitData = await submitResp.json();

if (!submitResp.ok) {
  console.log(`Submit FALLÓ (status ${submitResp.status}) en ${Date.now() - t0}ms`);
  console.log(JSON.stringify(submitData, null, 2));
}

console.log(`Submit OK en ${Date.now() - t0}ms — uuid=${submitData.uuid}`);

let resultado = null;

await new Promise((r) => setTimeout(r, 10000));
while (!resultado) {
  const resp = await fetch(
    `https://urlscan.io/api/v1/result/${submitData.uuid}/`,
    {
      headers: {
        'API-Key': URLSCAN_API_KEY
      }
    }
  );

  console.log(
    `poll @ ${Date.now() - t0}ms → status ${resp.status}`
  );

  if (resp.status === 200) {
    resultado = await resp.json();
    break;
  }

  if (resp.status !== 404) {
    const body = await resp.text();
    console.log(`Error ${resp.status}: ${body}`);
    break;
  }

  await new Promise((r) => setTimeout(r, 3000));
}

console.log(
  `Resultado disponible en ${Date.now() - t0}ms totales`
);
console.log(resultado)