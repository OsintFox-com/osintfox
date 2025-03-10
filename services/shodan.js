import { safeFetch } from '../utils/safeFetch.js';

const SHODAN_API_KEY = process.env.SHODAN_API_KEY;
const BASE_URL = 'https://api.shodan.io';

async function apiRequest(endpoint, params = {}) {
  const urlParams = new URLSearchParams({ key: SHODAN_API_KEY, ...params });
  const url = `${BASE_URL}${endpoint}?${urlParams}`;
  const response = await safeFetch(url);
  return response;
}

export const getHostInformation = (ip, history = false, minify = true) =>
  apiRequest(`/shodan/host/${ip}`, { history, minify });

export const searchShodan = (query, facets = '', page = 1) =>
  apiRequest('/shodan/host/search', { query, facets, page: page });

export const getHostCount = (query, facets = '') =>
  apiRequest('/shodan/host/count', { query, facets });

export const getSearchFilters = () =>
  apiRequest('/shodan/host/search/filters');
