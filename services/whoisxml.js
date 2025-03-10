import { safeFetch } from '../utils/safeFetch.js';

const WHOISXML_API_KEY = process.env.WHOISXML_API_KEY;

async function whoisApiRequest(baseUrl, params = {}) {
  const urlParams = new URLSearchParams({ apiKey: WHOISXML_API_KEY, ...params });
  const url = `${baseUrl}?${urlParams}`;
  return await safeFetch(url);
}

export const getDnsLookup = (domainName) =>
  whoisApiRequest('https://www.whoisxmlapi.com/api/v1', { domainName });

export const getDnsHistory = (domainName) =>
  whoisApiRequest('https://whois-history.whoisxmlapi.com/api/v1', { domainName, mode: 'purchase' });

export const getIPGeolocation = (ipAddress) =>
  whoisApiRequest('https://ip-geolocation.whoisxmlapi.com/api/v1', { ipAddress });

export const reverseIPLookup = (ip) =>
  whoisApiRequest('https://reverse-ip.whoisxmlapi.com/api/v1', { ip });

export const getSubdomains = (domain) =>
  whoisApiRequest('https://domains-subdomains-discovery.whoisxmlapi.com/api/v1', { domainName: domain });

export const reverseWhoisLookup = (searchTerm, mode = 'purchase') =>
  whoisApiRequest('https://reverse-whois.whoisxmlapi.com/api/v2', {
    searchType: 'current',
    basicSearchTerms: JSON.stringify({ include: [searchTerm] }),
    mode,
  });

export const getWhoisHistory = (domainName) =>
  whoisApiRequest('https://whois-history.whoisxmlapi.com/api/v1', { domainName, mode: 'purchase' });

export const verifyEmail = (emailAddress) =>
  whoisApiRequest('https://emailverification.whoisxmlapi.com/api/v3', { emailAddress });
