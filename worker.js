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

        case 'domain': {
          const [dnsLookupRes, dnsHistoryRes, subdomainsRes, revWhoisRes, whoisHistRes, hunterRes, leakcheckRes] = await Promise.allSettled([
            whoisxmlService.getDnsLookup(query, env),
            whoisxmlService.getDnsHistory(query, env),
            whoisxmlService.getSubdomains(query, env),
            whoisxmlService.reverseWhoisLookup(query, env),
            whoisxmlService.getWhoisHistory(query, env),
            fetchHunter(query, 'domain-search', env),
            fetchLeakcheck(query, 'domain', env),
          ]);

          results = {
            dnsLookup: dnsLookupRes.status === 'fulfilled' ? dnsLookupRes.value : { error: dnsLookupRes.reason.message },
            dnsHistory: dnsHistoryRes.status === 'fulfilled' ? dnsHistoryRes.value : { error: dnsHistoryRes.reason.message },
            subdomainsDiscovery: subdomainsRes.status === 'fulfilled' ? subdomainsRes.value : { error: subdomainsRes.reason.message },
            reverseWhois: revWhoisRes.status === 'fulfilled' ? revWhoisRes.value : { error: revWhoisRes.reason.message },
            whoisHistory: whoisHistRes.status === 'fulfilled' ? whoisHistRes.value : { error: whoisHistRes.reason.message },
            hunterDomainSearch: hunterRes.status === 'fulfilled' ? hunterRes.value : { error: hunterRes.reason.message },
            leakcheck: leakcheckRes.status === 'fulfilled' ? leakcheckRes.value : { error: leakcheckRes.reason.message },
          };
          break;
        }

        case 'email': {
          const [emailVerifyRes, hunterVerifyRes, hunterEnrichRes, leakcheckRes, osintIndustriesRes, lampyreRes] = await Promise.allSettled([
            whoisxmlService.verifyEmail(query, env),
            fetchHunter(query, 'email-verifier', env),
            fetchHunter(query, 'combined-enrichment', env),
            fetchLeakcheck(query, 'email', env),
            fetchOSINT(query, 'email', 60, false, env),
            lampyreSearch('email', query, env),
          ]);

          results = {
            emailVerification: emailVerifyRes.status === 'fulfilled' ? emailVerifyRes.value : { error: emailVerifyRes.reason.message },
            hunterVerifier: hunterVerifyRes.status === 'fulfilled' ? hunterVerifyRes.value : { error: hunterVerifyRes.reason.message },
            hunterEnrichment: hunterEnrichRes.status === 'fulfilled' ? hunterEnrichRes.value : { error: hunterEnrichRes.reason.message },
            leakcheck: leakcheckRes.status === 'fulfilled' ? leakcheckRes.value : { error: leakcheckRes.reason.message },
            osintIndustries: osintIndustriesRes.status === 'fulfilled' ? osintIndustriesRes.value : { error: osintIndustriesRes.reason.message },
            lampyre: lampyreRes.status === 'fulfilled' ? lampyreRes.value : { error: lampyreRes.reason.message },
          };
          break;
        }

        case 'username': {
          const [leakcheckRes, hunterPersonRes, osintIndustriesRes, lampyreRes] = await Promise.allSettled([
            fetchLeakcheck(query, 'username', env),
            fetchHunter(query, 'person-enrichment', env),
            fetchOSINT(query, 'username', 60, false, env),
            lampyreSearch('username', query, env),
          ]);

          results = {
            leakcheck: leakcheckRes.status === 'fulfilled' ? leakcheckRes.value : { error: leakcheckRes.reason.message },
            hunterPersonEnrichment: hunterPersonRes.status === 'fulfilled' ? hunterPersonRes.value : { error: hunterPersonRes.reason.message },
            osintIndustries: osintIndustriesRes.status === 'fulfilled' ? osintIndustriesRes.value : { error: osintIndustriesRes.reason.message },
            lampyre: lampyreRes.status === 'fulfilled' ? lampyreRes.value : { error: lampyreRes.reason.message },
          };
          break;
        }

        case 'phone': {
          const [leakcheckRes, osintIndustriesRes, lampyreRes] = await Promise.allSettled([
            fetchLeakcheck(query, 'phone', env),
            fetchOSINT(query, 'phone', 60, false, env),
            lampyreSearch('phone', query, env),
          ]);

          results = {
            leakcheck: leakcheckRes.status === 'fulfilled' ? leakcheckRes.value : { error: leakcheckRes.reason.message },
            osintIndustries: osintIndustriesRes.status === 'fulfilled' ? osintIndustriesRes.value : { error: osintIndustriesRes.reason.message },
            lampyre: lampyreRes.status === 'fulfilled' ? lampyreRes.value : { error: lampyreRes.reason.message },
          };
          break;
        }

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
