import { safeFetch } from '../utils/safeFetch.js';
import { API_KEYS } from '../config.js';

async function fetchLeakcheck(query, type = 'auto', limit = 100, offset = 0) {
  const urlParams = new URLSearchParams({
    type,
    limit: limit.toString(),
    offset: '0',
  });

  const url = `https://leakcheck.io/api/v2/query/${encodeURIComponent(query)}?${urlParams}`;
  return safeFetch(url, {
    headers: {
      "Accept": "application/json",
      "X-API-Key": API_KEYS.leakcheck
    }
  });
}

export { fetchLeakcheck };
