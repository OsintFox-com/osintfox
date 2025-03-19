import { fetchHunter } from './services/hunter';
import { fetchLeakcheck } from './services/leakcheck';
import { fetchOSINT } from './services/osintIndustries';
import { lampyreSearch } from './services/lampyre';
import * as shodanService from './services/shodan';
import * as whoisxmlService from './services/whoisxml';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== '/api/search') {
      return new Response(JSON.stringify({ error: 'Not found' }), { status: 404 });
    }

    const type = url.searchParams.get('type');
    const query = url.searchParams.get('query');

    if (!type || !query) {
      return new Response(JSON.stringify({ error: 'Missing type or query parameter' }), { status: 400 });
    }

    try {
      let results = {};

      switch (type.toLowerCase()) {
        case 'ip': {
          const [shodanRes, ipGeoRes, revIpRes, lampyreRes] = await Promise.allSettled([
            shodanService.getHostInformation(query, env),
            whoisxmlService.getIPGeolocation(query, env),
            whoisxmlService.reverseIPLookup(query, env),
            lampyreSearch('ip', query, env),
          ]);

          results = {
            shodanHostInfo: shodanRes.status === 'fulfilled' ? shodanRes.value : { error: shodanRes.reason.message },
            ipGeolocation: ipGeoRes.status === 'fulfilled' ? ipGeoRes.value : { error: ipGeoRes.reason.message },
            reverseIP: revIpRes.status === 'fulfilled' ? revIpRes.value : { error: revIpRes.reason.message },
            lampyre: lampyreRes.status === 'fulfilled' ? lampyreRes.value : { error: lampyreRes.reason.message },
          };
          break;
        }

        // (המשך את המימוש לכל סוגי הבקשות בדומה ל־case למעלה)

        default:
          return new Response(JSON.stringify({ error: 'Unsupported search type' }), { status: 400 });
      }

      return new Response(JSON.stringify({ success: true, results }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: 'Internal server error', details: error.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }
};
