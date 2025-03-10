import index from './index.js';

// Define globals used in index.js so tests can run without errors.
global.updateStats = async () => {};
global.cacheKey = 'test_cache_key';

// Import the module under test

describe('Index.fetch function', () => {
    test('returns 400 error for missing query or type parameter', async () => {
        const request = new Request('http://localhost/'); // no query or type
        const env = {
            OSINT_KV: {
                get: async () => null,
            },
        };
        const ctx = {};

        const response = await index.fetch(request, env, ctx);
        const data = await response.json();

        expect(response.status).toBe(400);
        expect(data.error).toBe("Missing query or type parameter");
    });
});