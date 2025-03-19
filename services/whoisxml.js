import { safeFetch } from '../utils/safeFetch.js';

const API_KEY = process.env.WHOISXML_API_KEY;

const whoisApiRequest = async (url, options = {}) => {
  return safeFetch(url, options);
};

export const getIPGeolocation = (ip) =>
  whoisApiRequest(`https://ip-geolocation.whoisxmlapi.com/api/v1?apiKey=${API_KEY}&ipAddress=${ip}`);

export const reverseIPLookup = (ip) =>
  whoisApiRequest(`https://reverse-ip.whoisxmlapi.com/api/v1?apiKey=${API_KEY}&ip=${ip}`);

export const getDnsLookup = (domain) =>
  whoisApiRequest(`https://www.whoisxmlapi.com/whoisserver/DNSService?apiKey=${API_KEY}&domainName=${domain}`);

export const getDnsHistory = (domain) =>
  whoisApiRequest(`https://whois-history.whoisxmlapi.com/api/v1?apiKey=${API_KEY}&domainName=${domain}`);

export const getSubdomains = (domain) =>
  whoisApiRequest('https://domains-subdomains-discovery.whoisxmlapi.com/api/v1', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      apiKey: API_KEY,
      subdomains: { include: [domain] },
    }),
  });

export const getWhoisHistory = (domain) =>
  whoisApiRequest(`https://whois-history.whoisxmlapi.com/api/v1?apiKey=${API_KEY}&domainName=${domain}`);

export const verifyEmail = (email) =>
  whoisApiRequest(`https://emailverification.whoisxmlapi.com/api/v2?apiKey=${API_KEY}&emailAddress=${email}`);

export const reverseWhoisLookup = (query) =>
  whoisApiRequest(`https://reverse-whois.whoisxmlapi.com/api/v2?apiKey=${API_KEY}&basicSearchTerms.include=${query}&mode=purchase`);
