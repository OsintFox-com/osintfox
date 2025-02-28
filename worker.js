addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const queryParam = url.searchParams.get("query");
  const ipParam = url.searchParams.get("ip");
  const serviceParam = url.searchParams.get("service"); // למשל: domain, email, ip או all
  const typeParam = url.searchParams.get("type");

  // האובייקט המאוחד שיחזיק את כל הנתונים – ללא שמות שירותים
  let unifiedResult = {
    domainInfo: {},
    breachInfo: [],
    ipInfo: {},
    osintInfo: {}
  };

  let tasks = [];

  // אם הוגדר פרמטר שירות – נבחר את הקריאות המתאימות
  if (serviceParam) {
    switch(serviceParam.toLowerCase()){
      case "domain":
        if(queryParam) {
          tasks.push(fetchWhois(queryParam).then(data => {
            unifiedResult.domainInfo = mapWhoisResponse(data);
          }));
          tasks.push(fetchLeakcheck(queryParam, "domain").then(data => {
            unifiedResult.breachInfo = mapBreachResponse(data);
          }));
        }
        break;
      case "email":
        if(queryParam) {
          tasks.push(fetchOSINT(queryParam, "email").then(data => {
            unifiedResult.osintInfo = mapOSINTResponse(data);
          }));
          tasks.push(fetchLeakcheck(queryParam, "email").then(data => {
            unifiedResult.breachInfo = mapBreachResponse(data);
          }));
          tasks.push(fetchHIBP(queryParam).then(data => {
            const hibpData = mapHibpResponse(data);
            unifiedResult.breachInfo = unifiedResult.breachInfo.concat(hibpData);
          }).catch(e => {}));
        }
        break;
      case "ip":
        if(ipParam) {
          tasks.push(fetchShodan(ipParam).then(data => {
            unifiedResult.ipInfo = mapShodanResponse(data);
          }));
        }
        break;
      case "all":
      default:
        if(queryParam) {
          if(queryParam.includes("@")){
            tasks.push(fetchOSINT(queryParam, "email").then(data => {
              unifiedResult.osintInfo = mapOSINTResponse(data);
            }));
            tasks.push(fetchLeakcheck(queryParam, "email").then(data => {
              unifiedResult.breachInfo = mapBreachResponse(data);
            }));
            tasks.push(fetchHIBP(queryParam).then(data => {
              const hibpData = mapHibpResponse(data);
              unifiedResult.breachInfo = unifiedResult.breachInfo.concat(hibpData);
            }).catch(e => {}));
          } else if(queryParam.includes(".")){
            tasks.push(fetchWhois(queryParam).then(data => {
              unifiedResult.domainInfo = mapWhoisResponse(data);
            }));
            tasks.push(fetchLeakcheck(queryParam, "domain").then(data => {
              unifiedResult.breachInfo = mapBreachResponse(data);
            }));
          }
        }
        if(ipParam) {
          tasks.push(fetchShodan(ipParam).then(data => {
            unifiedResult.ipInfo = mapShodanResponse(data);
          }));
        }
        break;
    }
  } else {
    // אם לא הוגדר service – ננסה לזהות באופן אוטומטי
    if(queryParam) {
      if(queryParam.includes("@")){
        tasks.push(fetchOSINT(queryParam, "email").then(data => {
          unifiedResult.osintInfo = mapOSINTResponse(data);
        }));
        tasks.push(fetchLeakcheck(queryParam, "email").then(data => {
          unifiedResult.breachInfo = mapBreachResponse(data);
        }));
        tasks.push(fetchHIBP(queryParam).then(data => {
          const hibpData = mapHibpResponse(data);
          unifiedResult.breachInfo = unifiedResult.breachInfo.concat(hibpData);
        }).catch(e => {}));
      } else if(queryParam.includes(".")){
        tasks.push(fetchWhois(queryParam).then(data => {
          unifiedResult.domainInfo = mapWhoisResponse(data);
        }));
        tasks.push(fetchLeakcheck(queryParam, "domain").then(data => {
          unifiedResult.breachInfo = mapBreachResponse(data);
        }));
      }
    }
    if(ipParam) {
      tasks.push(fetchShodan(ipParam).then(data => {
        unifiedResult.ipInfo = mapShodanResponse(data);
      }));
    }
  }

  await Promise.all(tasks);
  return new Response(JSON.stringify(unifiedResult, null, 2), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

/* פונקציות מיפוי – הן ממירות את הפלט הגולמי למבנה אחיד שאינו חושף את זהויות השירותים */

function mapWhoisResponse(data) {
  if(!data || !data.WhoisRecord) return {};
  const rec = data.WhoisRecord;
  return {
    domainName: rec.domainName || "",
    createdDate: rec.registryData ? rec.registryData.createdDate : (rec.audit ? rec.audit.createdDate : ""),
    updatedDate: rec.registryData ? rec.registryData.updatedDate : (rec.audit ? rec.audit.updatedDate : ""),
    expiresDate: rec.registryData ? rec.registryData.expiresDate : "",
    registrar: rec.registrarName || "",
    registrant: rec.registryData && rec.registryData.registrant ? {
      name: rec.registryData.registrant.name || "",
      email: rec.registryData.registrant.email || "",
      address: rec.registryData.registrant.street1 || ""
    } : {},
    nameServers: rec.registryData && rec.registryData.nameServers ? rec.registryData.nameServers.hostNames : []
  };
}

function mapBreachResponse(data) {
  if(!data || typeof data.found === "undefined") return [];
  let breaches = [];
  if(data.found && Array.isArray(data.result)) {
    for (let item of data.result) {
      breaches.push({
        source: item.source && item.source.name ? item.source.name : "unknown",
        breachDate: item.source && item.source.breach_date ? item.source.breach_date : "",
        fields: item.fields || [],
        credentials: {
          password: item.password || "",
          email: item.email || "",
          username: item.username || "",
          name: item.first_name || item.name || ""
        }
      });
    }
  }
  return breaches;
}

function mapOSINTResponse(data) {
  if(!data || !Array.isArray(data)) return {};
  let unified = { modules: [] };
  for (let mod of data) {
    unified.modules.push({
      module: mod.module || "",
      status: mod.status || "",
      data: mod.data || {}
    });
  }
  return unified;
}

function mapShodanResponse(data) {
  if(!data) return {};
  return {
    ip: data.ip_str || "",
    organization: data.org || "",
    hostnames: data.hostnames || [],
    location: data.location ? {
      city: data.location.city || "",
      region: data.location.region_code || "",
      country: data.location.country_name || "",
      latitude: data.location.latitude || "",
      longitude: data.location.longitude || ""
    } : {},
    ports: data.ports || []
  };
}

function mapHibpResponse(data) {
  if(!data || !Array.isArray(data)) return [];
  let breaches = [];
  for (let breach of data) {
    breaches.push({
      name: breach.Name || "",
      breachDate: breach.BreachDate || "",
      description: breach.Description || ""
    });
  }
  return breaches;
}

/* פונקציות קריאה לכל API בהתאם לתיעוד */

async function fetchWhois(query) {
  const url = new URL("https://www.whoisxmlapi.com/whoisserver/WhoisService");
  url.searchParams.set("apiKey", WHOISXML_API_KEY);
  url.searchParams.set("domainName", query);
  url.searchParams.set("outputFormat", "JSON");
  const response = await fetch(url.toString());
  return response.json();
}

async function fetchLeakcheck(query, type) {
  const url = new URL(`https://leakcheck.io/api/v2/query/${encodeURIComponent(query)}`);
  url.searchParams.set("type", type);
  const response = await fetch(url.toString(), {
    headers: {
      "Accept": "application/json",
      "X-API-Key": LEAKCHECK_API_KEY
    }
  });
  return response.json();
}

async function fetchOSINT(query, type) {
  const url = new URL("https://api.osint.industries/v2/request");
  url.searchParams.set("type", type);
  url.searchParams.set("query", query);
  url.searchParams.set("timeout", "60");
  const response = await fetch(url.toString(), {
    headers: {
      "accept": "application/json",
      "api-key": OSINT_API_KEY
    }
  });
  return response.json();
}

async function fetchShodan(ip) {
  const url = new URL(`https://api.shodan.io/shodan/host/${ip}`);
  url.searchParams.set("key", SHODAN_API_KEY);
  const response = await fetch(url.toString());
  return response.json();
}

async function fetchHIBP(query) {
  const url = new URL(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(query)}`);
  const response = await fetch(url.toString(), {
    headers: {
      "hibp-api-key": HIBP_API_KEY,
      "User-Agent": "CloudflareWorker/1.0"
    }
  });
  return response.json();
}
