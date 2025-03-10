import { safeFetch } from '../utils/safeFetch.js';
import { API_KEYS } from '../config.js';

async function fetchHunter(query, type, params = {}) {
  let endpoint;
  const queryParams = new URLSearchParams({ api_key: API_KEYS.hunter });

  switch (type) {
    case 'domain-search':
      endpoint = 'domain-search';
      queryParams.set('domain', query);
      if (params.limit) queryParams.set('limit', params.limit);
      if (params.offset) queryParams.set('offset', params.offset);
      if (params.type) queryParams.set('type', params.type);
      break;

    case 'email-finder':
      endpoint = 'email-finder';
      queryParams.set('domain', params.domain);
      queryParams.set('first_name', params.first_name);
      queryParams.set('last_name', params.last_name);
      break;

    case 'email-verifier':
      endpoint = 'email-verifier';
      queryParams.set('email', query);
      break;

    case 'company-enrichment':
      endpoint = 'companies/find';
      queryParams.set('domain', query);
      break;

    case 'person-enrichment':
      endpoint = 'people/find';
      queryParams.set('email', query);
      break;

    case 'combined-enrichment':
      endpoint = 'combined/find';
      queryParams.set('email', query);
      break;

    case 'email-count':
      endpoint = 'email-count';
      queryParams.set('domain', query);
      break;

    case 'account-info':
      endpoint = 'account';
      break;

    default:
      throw new Error(`Invalid request type: ${type}`);
  }

  const url = `https://api.hunter.io/v2/${endpoint}?${queryParams}`;
  return safeFetch(url);
}

export { fetchHunter };
