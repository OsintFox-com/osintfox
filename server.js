import { Router } from 'itty-router';
import * as virustotalService from './virustotal.js';

const router = Router();

router.get('/api/virustotal/file/:hash', async ({ params }) => {
  try {
    const result = await virustotalService.getFileReport(params.hash);
    return new Response(JSON.stringify(result), { status: 200 });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), { status: 500 });
  }
});

router.get('/api/virustotal/url', async (request) => {
  const url = new URL(request.url).searchParams.get('url');

  try {
    const encodedUrl = btoa(url).replace(/=+$/, '');
    const result = await virustotalService.getUrlReport(encodedUrl);
    return new Response(JSON.stringify(result), { status: 200 });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), { status: 500 });
  }
});

router.post('/api/virustotal/scan', async (request) => {
  const { url } = await request.json();
  try {
    const result = await virustotalService.scanUrl(url);
    return new Response(JSON.stringify(result), { status: 200 });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), { status: 500 });
  }
});

router.all('*', () => new Response('OSINTFox API Endpoint', { status: 404 }));

export default {
  fetch: router.handle
};