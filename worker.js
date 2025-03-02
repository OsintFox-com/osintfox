export default {
  async fetch(request, env, ctx) {
    try {
      // Parse URL and query parameters
      const url = new URL(request.url);
      const params = new URLSearchParams(url.search);
      const normalizedParams = {};
      for (const [key, value] of params.entries()) {
        normalizedParams[key.toLowerCase()] = value;
      }

      // Retrieve required parameters: query and type
      const query = normalizedParams["query"] ? normalizedParams["query"].trim() : "";
      const queryType = normalizedParams["type"]
        ? normalizedParams["type"].trim().toLowerCase()
        : "";
      if (!query || !queryType) {
        return new Response(
          JSON.stringify({ error: "Missing query or type parameter" }),
          {
            status: 400,
            headers: { "Content-Type": "application/json" },
          }
        );
      }

      // Create a unified cache key
      const cacheKey = `osint:${queryType}:${query}`;
      const cachedAggregate = await env.OSINT_KV.get(cacheKey, { type: "json" });
      if (cachedAggregate) {
        return new Response(JSON.stringify(cachedAggregate, null, 2), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }

      // List of free email domains – these do not warrant standard Whois/Hunter calls.
      const freeEmailDomains = [
        "gmail.com",
        "hotmail.com",
        "yahoo.com",
        "outlook.com",
        "live.com",
      ];

      // Object to store the aggregated results
      const results = {
        domainInfo: null,
        breachInfo: null,
        ipInfo: null,
        osintInfo: null,
        hunterInfo: null,
        recommendations: [],
      };

      // Helper function to call an external API and cache its result
      async function fetchAndCache(serviceKey, fetchFn) {
        const serviceCacheKey = `${cacheKey}:${serviceKey}`;
        const cachedData = await env.OSINT_KV.get(serviceCacheKey, { type: "json" });
        if (cachedData) return cachedData;
        try {
          const data = await fetchFn();
          await env.OSINT_KV.put(serviceCacheKey, JSON.stringify(data), { expirationTtl: 600 });
          return data;
        } catch (error) {
          console.error(`Error in service "${serviceKey}":`, error);
          return null;
        }
      }

      // Define groups of services based on query type
      const leakCheckParams = ["email", "domain", "username", "phone", "hash", "password"];
      const osintIndustriesParams = ["email", "username", "phone"];
      // For Whois: handle only domain and IP queries (or email if corporate)
      const whoisParams = ["domain", "ip"];
      // For Hunter: used for corporate emails and domains
      const hunterParams = ["email", "domain"];
      // For Shodan: supports IP queries
      const shodanParams = ["ip"];

      // Array to collect all API call tasks
      const tasks = [];

      // LeakCheck call (for breach data)
      if (leakCheckParams.includes(queryType)) {
        tasks.push(
          (async () => {
            results.breachInfo = await fetchAndCache("leakcheck", async () => {
              const leakUrl = `https://leakcheck.io/api/v2/query/${encodeURIComponent(query)}?type=${encodeURIComponent(queryType)}`;
              const response = await fetch(leakUrl, {
                headers: { "X-API-Key": env.LeakCheck_API_KEY },
              });
              if (!response.ok)
                throw new Error(`Leakcheck API error: ${response.statusText}`);
              return response.json();
            });
          })()
        );
      }

      // OSINT Industries call
      if (osintIndustriesParams.includes(queryType)) {
        tasks.push(
          (async () => {
            results.osintInfo = await fetchAndCache("osint", async () => {
              const osintUrl = `https://api.osint.industries/v2/request?type=${encodeURIComponent(queryType)}&query=${encodeURIComponent(query)}&timeout=60`;
              const response = await fetch(osintUrl, {
                headers: {
                  accept: "application/json",
                  "api-key": env.Osint_Industries_API_KEY,
                },
              });
              if (!response.ok)
                throw new Error(`OSINT Industries API error: ${response.statusText}`);
              return response.json();
            });
          })()
        );
      }

      // WhoisXML call handling
      if (queryType === "email") {
        // Extract domain from email
        const emailDomain = query.split("@")[1]?.toLowerCase();
        if (emailDomain && freeEmailDomains.includes(emailDomain)) {
          // For free emails, use Reverse Whois instead of standard Whois
          tasks.push(
            (async () => {
              results.domainInfo = await fetchAndCache("reverse_whois", async () => {
                return await fetchReverseWhois(query);
              });
            })()
          );
        } else {
          // For corporate emails, call standard Whois
          tasks.push(
            (async () => {
              results.domainInfo = await fetchAndCache("whois", async () => {
                return await fetchWhois(query, queryType);
              });
            })()
          );
        }
      } else if (whoisParams.includes(queryType)) {
        tasks.push(
          (async () => {
            results.domainInfo = await fetchAndCache("whois", async () => {
              return await fetchWhois(query, queryType);
            });
          })()
        );
      }

      // Shodan call for IP addresses
      if (shodanParams.includes(queryType)) {
        tasks.push(
          (async () => {
            results.ipInfo = await fetchAndCache("shodan", async () => {
              const shodanUrl = `https://api.shodan.io/shodan/host/${encodeURIComponent(query)}?key=${env.Shodan_API_KEY}`;
              const response = await fetch(shodanUrl);
              if (!response.ok)
                throw new Error(`Shodan API error: ${response.statusText}`);
              return response.json();
            });
          })()
        );
      }

      // Hunter.io call for corporate emails or domains
      if (hunterParams.includes(queryType)) {
        if (queryType === "email") {
          const emailDomain = query.split("@")[1]?.toLowerCase();
          if (emailDomain && !freeEmailDomains.includes(emailDomain)) {
            // For corporate email, use Hunter.io Email Verifier
            tasks.push(
              (async () => {
                results.hunterInfo = await fetchAndCache("hunter", async () => {
                  return await fetchHunter(query, queryType);
                });
              })()
            );
          }
          // For free email domains, do not call Hunter.io
        } else {
          tasks.push(
            (async () => {
              results.hunterInfo = await fetchAndCache("hunter", async () => {
                return await fetchHunter(query, queryType);
              });
            })()
          );
        }
      }

      // Run all API calls concurrently
      await Promise.allSettled(tasks);

      // Cache the aggregated result
      await env.OSINT_KV.put(cacheKey, JSON.stringify(results), { expirationTtl: 600 });

      return new Response(JSON.stringify(results, null, 2), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    } catch (error) {
      console.error("Unhandled error:", error);
      return new Response(JSON.stringify({ error: "Internal Server Error" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  }
};

// Helper functions

async function fetchWhois(query, type) {
  // Standard WhoisXML API call
  const url = `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${env.WhoisXML_API_KEY}&domainName=${encodeURIComponent(query)}&outputFormat=json`;
  const response = await fetch(url);
  if (!response.ok)
    throw new Error(`Whois API request failed: ${response.statusText}`);
  return response.json();
}

async function fetchReverseWhois(email) {
  // Reverse Whois API call per documentation
  const url = "https://reverse-whois.whoisxmlapi.com/api/v2";
  const body = {
    apiKey: env.WhoisXML_API_KEY,
    searchType: "current",
    mode: "purchase",
    punycode: true,
    basicSearchTerms: {
      include: [email],
    },
  };
  const init = {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
  const response = await fetch(url, init);
  if (!response.ok)
    throw new Error(`Reverse Whois API request failed: ${response.statusText}`);
  return response.json();
}

async function fetchLeakcheck(query, type) {
  const url = `https://leakcheck.io/api/v2/query/${encodeURIComponent(query)}?type=${encodeURIComponent(type)}`;
  const response = await fetch(url, {
    headers: { "X-API-Key": env.LeakCheck_API_KEY },
  });
  if (!response.ok)
    throw new Error(`Leakcheck API request failed: ${response.statusText}`);
  return response.json();
}

async function fetchOSINT(query, type) {
  const url = `https://api.osint.industries/v2/request?type=${encodeURIComponent(type)}&query=${encodeURIComponent(query)}&timeout=60`;
  const response = await fetch(url, {
    headers: {
      accept: "application/json",
      "api-key": env.Osint_Industries_API_KEY,
    },
  });
  if (!response.ok)
    throw new Error(`OSINT Industries API request failed: ${response.statusText}`);
  return response.json();
}

async function fetchShodan(query) {
  const url = `https://api.shodan.io/shodan/host/${encodeURIComponent(query)}?key=${env.Shodan_API_KEY}`;
  const response = await fetch(url);
  if (!response.ok)
    throw new Error(`Shodan API request failed: ${response.statusText}`);
  return response.json();
}

async function fetchHunter(query, type) {
  // For email queries, use Hunter.io Email Verifier
  if (type === "email") {
    const url = `https://api.hunter.io/v2/email-verifier?api_key=${env.HunterIO_API_KEY}&email=${encodeURIComponent(query)}`;
    const response = await fetch(url);
    if (!response.ok)
      throw new Error(`Hunter.io API request failed: ${response.statusText}`);
    return response.json();
  } else {
    // For domain queries, use Hunter.io Domain Search
    const url = `https://api.hunter.io/v2/domain-search?api_key=${env.HunterIO_API_KEY}&domain=${encodeURIComponent(query)}`;
    const response = await fetch(url);
    if (!response.ok)
      throw new Error(`Hunter.io API request failed: ${response.statusText}`);
    return response.json();
  }
}