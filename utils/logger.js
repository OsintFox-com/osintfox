async function updateStats(env, statKey) {
    const current = parseInt(await env.OSINT_KV.get(`stats:${statKey}`)) || 0;
    await env.OSINT_KV.put(`stats:${statKey}`, (current + 1).toString());
  }
  
  export { updateStats };