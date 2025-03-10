# Testing Instructions

1. Install dependencies:
   ```
   npm install
   ```

2. Run tests locally:
   ```
   npm test
   ```

3. Ensure your environment variables (HUNTER_API_KEY, LEAKCHECK_API_KEY, SHODAN_API_KEY, WHOISXML_API_KEY) are set.  
   These keys are automatically provided when running via our GitHub Actions workflow.

4. Check the GitHub Actions "Test" workflow logs on push or pull request for CI test results.
