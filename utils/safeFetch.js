export async function safeFetch(url, options = {}, retries = 3) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const response = await fetch(url, options);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return await response.json();
    } catch (error) {
      if (attempt === retries) {
        console.error(`Request failed after ${retries} attempts:`, error);
        throw error;
      }
      console.warn(`Retrying request (${attempt}/${retries}):`, error.message);
    }
  }
}
