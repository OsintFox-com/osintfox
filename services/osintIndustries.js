import { safeFetch } from '../utils/safeFetch.js';
import { API_KEYS } from '../config.js';

async function fetchOSINT(query, type = 'email', timeout = 60, useStream = false) {
  const baseUrl = `https://api.osint.industries/v2/request${useStream ? '/stream' : ''}`;
  const url = `${baseUrl}?type=${encodeURIComponent(type)}&query=${encodeURIComponent(query)}&timeout=${timeout}`;

  if (!useStream) {
    return safeFetch(url, {
      headers: {
        "Accept": "application/json",
        "api-key": API_KEYS.osintindustries
      }
    });
  } else {
    const res = await fetch(url, {
      headers: {
        "Accept": "application/json",
        "api-key": API_KEYS.osintindustries
      }
    });

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    const results = [];

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop();

      for (const line of lines) {
        if (line.trim()) {
          results.push(JSON.parse(line));
        }
      }
    }

    return results;
  }
}

export { fetchOSINT };
