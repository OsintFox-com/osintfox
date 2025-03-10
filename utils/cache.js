const cacheDurations = {
    whois: 3600,
    reverse_whois: 3600,
    leakcheck: 600,
    shodan: 86400,
    hunter: 3600,
    osint: 600
  };
  
  async function putCache(env, key, data, serviceKey) {
    const ttl = cacheDurations[serviceKey] || 600;
    await env.OSINT_KV.put(key, JSON.stringify(data), { expirationTtl: ttl });
  }
  
  export { cacheDurations, putCache };