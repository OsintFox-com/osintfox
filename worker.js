export default {
  async fetch(request) {
    const url = new URL(request.url);
    const params = new URLSearchParams(url.searchParams);

    // Normalize all query parameters to lowercase to avoid case sensitivity issues
    const normalizedParams = {};
    for (const [key, value] of params.entries()) {
      normalizedParams[key.toLowerCase()] = value;
    }

    const query = normalizedParams["query"];
    const queryType = normalizedParams["type"];
    const service = normalizedParams["service"];

    if (!query || !queryType) {
      return new Response(JSON.stringify({ error: "Missing query or type parameter" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }

    if (typeof query !== "string" || typeof queryType !== "string") {
      return new Response(JSON.stringify({ error: "Invalid query or type parameter format" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }

    const cacheKey = `osint:${queryType}:${query}`;
    const cachedResponse = await OSINT_KV.get(cacheKey, { type: "json" });
    if (cachedResponse) {
      return new Response(JSON.stringify(cachedResponse, null, 2), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }

    let results = {
      domainInfo: {},
      breachInfo: [],
      ipInfo: {},
      osintInfo: {},
      hunterInfo: {},
      recommendations: []
    };

    let tasks = [];

    const fetchAndCache = async (fn, key, resultField) => {
      try {
        const data = await fn();
        results[resultField] = data;
        await OSINT_KV.put(key, JSON.stringify(data));
      } catch (error) {
        console.error(`Error fetching ${resultField}:`, error);
      }
    };

    const leakCheckParams = ["email", "domain", "username", "phone", "hash", "password"];
    const osintIndustriesParams = ["email", "username", "phone"];
    const whoisParams = ["domain", "ip", "email", "registrar", "dns", "status", "contacts"];
    const shodanParams = ["ip"];
    const hunterParams = ["email", "domain"];

    if (leakCheckParams.includes(queryType)) {
      tasks.push(fetchAndCache(() => fetchLeakcheck(query, queryType), cacheKey, 'breachInfo'));
    }
    if (osintIndustriesParams.includes(queryType)) {
      tasks.push(fetchAndCache(() => fetchOSINT(query, queryType), cacheKey, 'osintInfo'));
    }
    if (whoisParams.includes(queryType)) {
      tasks.push(fetchAndCache(() => fetchWhois(query, queryType), cacheKey, 'domainInfo'));
    }
    if (shodanParams.includes(queryType)) {
      tasks.push(fetchAndCache(() => fetchShodan(query), cacheKey, 'ipInfo'));
    }
    if (hunterParams.includes(queryType)) {
      tasks.push(fetchAndCache(() => fetchHunter(query, queryType), cacheKey, 'hunterInfo'));
    }

    await Promise.allSettled(tasks);

    return new Response(JSON.stringify(results, null, 2), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  }
};

async function fetchWhois(query, type) {
  const url = `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=YOUR_API_KEY&domainName=${query}&outputFormat=json`;
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Whois API request failed: ${response.statusText}`);
  return response.json();
}

async function fetchLeakcheck(query, type) {
  const url = `https://leakcheck.io/api/v2/query/${encodeURIComponent(query)}?type=${type}`;
  const response = await fetch(url, { headers: { "X-API-Key": "YOUR_API_KEY" } });
  if (!response.ok) throw new Error(`Leakcheck API request failed: ${response.statusText}`);
  return response.json();
}

async function fetchOSINT(query, type) {
  const url = `https://api.osint.industries/v2/request?type=${type}&query=${query}&timeout=60`;
  const response = await fetch(url, { headers: { "accept": "application/json", "api-key": "YOUR_API_KEY" } });
  if (!response.ok) throw new Error(`OSINT API request failed: ${response.statusText}`);
  return response.json();
}

async function fetchShodan(ip) {
  const url = `https://api.shodan.io/shodan/host/${ip}?key=YOUR_API_KEY`;
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Shodan API request failed: ${response.statusText}`);
  return response.json();
}

async function fetchHunter(query, type) {
  const url = `https://api.hunter.io/v2/${type}?api_key=YOUR_API_KEY&query=${query}`;
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Hunter.io API request failed: ${response.statusText}`);
  return response.json();
}
