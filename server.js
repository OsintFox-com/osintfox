import express from 'express';
import dotenv from 'dotenv';
import { fetchHunter } from './services/hunter.js';
import { fetchLeakcheck } from './services/leakcheck.js';
import { fetchOSINT } from './services/osintIndustries.js';
import * as shodanService from './services/shodan.js';
import * as whoisxmlService from './services/whoisxml.js';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

app.get('/api/search', async (req, res) => {
  const { type, query } = req.query;

  if (!type || !query) {
    return res.status(400).json({ error: 'Missing type or query parameter' });
  }

  try {
    const results = {};

    switch (type.toLowerCase()) {
      case 'ip':
        results.shodanHostInfo = await shodanService.getHostInformation(query);
        results.ipGeolocation = await whoisxmlService.getIPGeolocation(query);
        results.reverseIP = await whoisxmlService.reverseIPLookup(query);
        break;

      case 'domain':
        results.dnsLookup = await whoisxmlService.getDnsLookup(query);
        results.dnsHistory = await whoisxmlService.getDnsHistory(query);
        results.subdomainsDiscovery = await whoisxmlService.getSubdomains(query);
        results.reverseWhois = await whoisxmlService.reverseWhoisLookup(query);
        results.whoisHistory = await whoisxmlService.getWhoisHistory(query);
        results.hunterDomainSearch = await fetchHunter(query, 'domain-search');
        results.leakcheck = await fetchLeakcheck(query, 'domain');
        break;

      case 'email':
        results.emailVerification = await whoisxmlService.verifyEmail(query);
        results.hunterVerifier = await fetchHunter(query, 'email-verifier');
        results.hunterEnrichment = await fetchHunter(query, 'combined-enrichment');
        results.leakcheck = await fetchLeakcheck(query, 'email');
        try {
          results.osintIndustries = await fetchOSINT(query, 'email', 60, true);
        } catch (streamError) {
          results.osintIndustries = { error: streamError.message };
        }
        break;

      case 'username':
        results.leakcheck = await fetchLeakcheck(query, 'username');
        results.hunterPersonEnrichment = await fetchHunter(query, 'person-enrichment');
        try {
          results.osintIndustries = await fetchOSINT(query, 'username', 60, true);
        } catch (streamError) {
          results.osintIndustries = { error: streamError.message };
        }
        break;

      case 'phone':
        results.leakcheck = await fetchLeakcheck(query, 'phone');
        try {
          results.osintIndustries = await fetchOSINT(query, 'phone', 60, true);
        } catch (streamError) {
          results.osintIndustries = { error: streamError.message };
        }
        break;

      case 'hash':
        results.leakcheck = await fetchLeakcheck(query, 'hash');
        break;

      case 'password':
        results.leakcheck = await fetchLeakcheck(query, 'password');
        break;

      case 'origin':
        results.leakcheck = await fetchLeakcheck(query, 'origin');
        break;

      case 'keyword':
        results.leakcheck = await fetchLeakcheck(query, 'keyword');
        break;

      default:
        return res.status(400).json({ error: 'Unsupported search type' });
    }

    res.json({ success: true, results });
  } catch (error) {
    console.error('OSINTFox API Error:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(PORT, () => {
  console.log(`OSINTFox API listening on port ${PORT} 🚀`);
});
