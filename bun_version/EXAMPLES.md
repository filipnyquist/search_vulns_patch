# Examples

This directory contains examples of how to use the search_vulns Bun.js/TypeScript implementation.

## API Examples

### Using the REST API

Start the server:
```bash
bun run server
```

Then use curl or any HTTP client:

```bash
# Health check
curl http://localhost:5000/health

# Search for a CVE
curl "http://localhost:5000/api/search?q=CVE-2024-27286"

# Search for software
curl "http://localhost:5000/api/search?q=Sudo%201.8.2"

# POST request with options
curl -X POST http://localhost:5000/api/search \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Apache 2.4.39",
    "ignore_general_product_vulns": false,
    "include_single_version_vulns": false,
    "include_patched": false
  }'

# Batch search
curl -X POST http://localhost:5000/api/batch-search \
  -H "Content-Type: application/json" \
  -d '{
    "queries": ["CVE-2024-27286", "GHSA-hfjr-m75m-wmh7", "Sudo 1.8.2"]
  }'
```

### Using as a Library

You can also use search_vulns as a library in your Bun.js/TypeScript projects:

```typescript
import { searchVulns, loadConfig } from './src/index';

// Load configuration
const config = await loadConfig();

// Search for vulnerabilities
const result = await searchVulns(
  'CVE-2024-27286',
  null,
  null,
  null,
  false,
  false,
  false,
  false,
  config
);

console.log('Found vulnerabilities:', Object.keys(result.vulns));

// Access vulnerability details
for (const [vulnId, vuln] of Object.entries(result.vulns)) {
  console.log(`${vulnId}: ${vuln.description}`);
  console.log(`  CVSS: ${vuln.cvss} (v${vuln.cvssVer})`);
  console.log(`  Published: ${vuln.published}`);
}
```

## CLI Examples

```bash
# Search for a vulnerability
bun run cli -q "CVE-2024-27286"

# Search for software
bun run cli -q "Sudo 1.8.2"

# Multiple queries
bun run cli -q "CVE-2024-27286" -q "GHSA-hfjr-m75m-wmh7"

# JSON output
bun run cli -q "Apache 2.4.39" -f json

# Save to file
bun run cli -q "Moodle 3.4.0" -o results.txt

# With options
bun run cli -q "Wordpress 5.7.2" --ignore-general-product-vulns
```

## Testing

Run the test suite:
```bash
bun test
```

Run tests with coverage:
```bash
bun test --coverage
```
