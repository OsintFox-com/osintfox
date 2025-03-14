import { API_KEYS } from './config';

const BASE_URL = 'https://www.virustotal.com/api/v3';

async function vtRequest(endpoint, params = {}) {
  const url = `${BASE_URL}${endpoint}?${new URLSearchParams(params)}`;
  const response = await fetch(url, {
    headers: {
      'x-apikey': API_KEYS.virustotal
    }
  });

  if (!response.ok) {
    throw new Error(`VirusTotal API Error: ${response.statusText}`);
  }

  return response.json();
}

export const getFileReport = (hash) => vtRequest(`/files/${hash}`);

export const getUrlReport = (urlId) => vtRequest(`/urls/${urlId}`);

export const scanUrl = async (urlToScan) => {
  const response = await fetch(`${BASE_URL}/urls`, {
    method: 'POST',
    headers: {
      'x-apikey': API_KEYS.virustotal,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({ url: urlToScan })
  });

  if (!response.ok) {
    throw new Error(`VirusTotal URL Scan Error: ${response.statusText}`);
  }

  return response.json();
};