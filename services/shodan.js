import { safeFetch } from '../utils/safeFetch.js';

const SHODAN_API_KEY = process.env.SHODAN_API_KEY;
const BASE_URL = 'https://api.shodan.io';

async function apiRequest(endpoint, params = {}) {
  const urlParams = new URLSearchParams({ key: SHODAN_API_KEY, ...params });
  const url = `${BASE_URL}${endpoint}?${urlParams}`;
  try {
    return await safeFetch(url);
  } catch (error) {
    if (error.message.includes('status: 404')) {
      return { error: 'IP not found in Shodan', status: 404 };
    }
    throw error;
  }
}

export const getHostInformation = (ip, history = false, minify = true) =>
  apiRequest(`/shodan/host/${encodeURIComponent(ip)}`, { history, minify });

export const searchShodan = (query, facets = '', page = 1) =>
  apiRequest('/shodan/host/search', { query, facets, page });

export const getHostCount = (query, facets = '') =>
  apiRequest('/shodan/host/count', { query, facets });

export const getSearchFilters = () =>
  apiRequest('/shodan/host/search/filters');
