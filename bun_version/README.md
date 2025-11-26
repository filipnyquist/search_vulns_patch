# search_vulns - Bun.js/TypeScript Implementation

This is a Bun.js/TypeScript implementation of search_vulns, a tool to search for known vulnerabilities in software using software titles or CPE 2.3 strings.

## Features

- 🚀 Fast and efficient vulnerability search powered by Bun.js
- 🔍 Search by software name/version or CVE/GHSA IDs
- 📊 REST API for programmatic access
- 💻 CLI interface for command-line usage
- 🗄️ SQLite database support
- 🎯 TypeScript for type safety

## Prerequisites

- [Bun](https://bun.sh) >= 1.0.0

## Installation

1. Install dependencies:
```bash
cd bun_version
bun install
```

2. The project requires database files from the main Python implementation. You can either:
   - Copy the database files from the Python version's `resources/` directory
   - Or download them using the Python version's update command: `search_vulns -u`

The databases should be placed in `bun_version/resources/`:
- `vulndb.db3` - Vulnerability database
- `productdb.db3` - Product database

## Usage

### CLI Usage

Search for vulnerabilities by software name:
```bash
bun run cli -q "Sudo 1.8.2"
```

Search for specific CVE/GHSA IDs:
```bash
bun run cli -q "CVE-2024-27286, GHSA-hfjr-m75m-wmh7"
```

Output as JSON:
```bash
bun run cli -q "Apache 2.4.39" -f json
```

Save output to file:
```bash
bun run cli -q "Moodle 3.4.0" -o results.txt
```

#### CLI Options

```
-h, --help                              Show help message
-q, --query <QUERY>                     Search query (software name or vulnerability ID)
-c, --config <FILE>                     Config file to use (default: config.json)
-V, --version                           Print version
-f, --format <txt|json>                 Output format (default: txt)
-o, --output <FILE>                     Write output to file
--ignore-general-product-vulns          Ignore vulnerabilities affecting general products
--include-single-version-vulns          Include single-version vulnerabilities
--include-patched                       Include patched vulnerabilities
```

### API Server Usage

Start the API server:
```bash
bun run server
```

The server will start on `http://localhost:5000` by default. You can change the port using the `PORT` environment variable:
```bash
PORT=8080 bun run server
```

#### API Endpoints

##### GET /health
Health check endpoint
```bash
curl http://localhost:5000/health
```

Response:
```json
{
  "status": "ok",
  "version": "0.8.2",
  "service": "search_vulns_bun"
}
```

##### GET /api/version
Get API version
```bash
curl http://localhost:5000/api/version
```

##### GET /api/search
Search for vulnerabilities (GET request)
```bash
curl "http://localhost:5000/api/search?q=CVE-2024-27286"
curl "http://localhost:5000/api/search?q=Sudo%201.8.2"
```

Query parameters:
- `q` or `query` - Search query (required)
- `ignore_general_product_vulns` - Ignore general product vulnerabilities (optional, boolean)
- `include_single_version_vulns` - Include single version vulnerabilities (optional, boolean)
- `include_patched` - Include patched vulnerabilities (optional, boolean)

##### POST /api/search
Search for vulnerabilities (POST request)
```bash
curl -X POST http://localhost:5000/api/search \
  -H "Content-Type: application/json" \
  -d '{"query": "Sudo 1.8.2"}'
```

Request body:
```json
{
  "query": "Sudo 1.8.2",
  "ignore_general_product_vulns": false,
  "include_single_version_vulns": false,
  "include_patched": false
}
```

##### POST /api/batch-search
Search for multiple queries at once
```bash
curl -X POST http://localhost:5000/api/batch-search \
  -H "Content-Type: application/json" \
  -d '{"queries": ["CVE-2024-27286", "Sudo 1.8.2"]}'
```

Request body:
```json
{
  "queries": ["CVE-2024-27286", "GHSA-hfjr-m75m-wmh7", "Sudo 1.8.2"],
  "ignore_general_product_vulns": false,
  "include_single_version_vulns": false,
  "include_patched": false
}
```

#### API Response Format

```json
{
  "product_ids": {
    "cpe": ["cpe:2.3:a:sudo_project:sudo:1.8.2:*:*:*:*:*:*:*"]
  },
  "vulns": {
    "CVE-2019-14287": {
      "id": "CVE-2019-14287",
      "match_reason": "version_in_range",
      "match_sources": ["nvd"],
      "description": "In Sudo before 1.8.28, an attacker...",
      "published": "2019-10-17 01:15:10",
      "modified": "2023-11-07 03:06:50",
      "cvss_ver": "3.1",
      "cvss": "8.8",
      "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
      "exploits": ["https://www.exploit-db.com/exploits/47502"],
      "cisa_known_exploited": false,
      "aliases": {
        "CVE-2019-14287": "https://nvd.nist.gov/vuln/detail/CVE-2019-14287"
      },
      "tracked_by": ["nvd"],
      "epss": "",
      "reported_patched_by": []
    }
  },
  "pot_product_ids": {}
}
```

## Configuration

The configuration file `config.json` contains database paths and module settings:

```json
{
  "DATABASE_CONNECTION": {
    "TYPE": "sqlite"
  },
  "VULN_DATABASE": {
    "NAME": "resources/vulndb.db3"
  },
  "PRODUCT_DATABASE": {
    "NAME": "resources/productdb.db3"
  },
  "MODULES": {
    "cpe_search.search_vulns_cpe_search": {
      "NVD_API_KEY": "",
      "CPE_SEARCH_COUNT": 10,
      "CPE_SEARCH_THRESHOLD": 0.68
    }
  }
}
```

## Development

Run the server in development mode with auto-reload:
```bash
bun run dev
```

Run tests:
```bash
bun test
```

## Project Structure

```
bun_version/
├── src/
│   ├── types/
│   │   ├── vulnerability.ts    # Vulnerability types and classes
│   │   └── config.ts           # Configuration types
│   ├── utils/
│   │   ├── database.ts         # Database utilities
│   │   └── config.ts           # Config loader
│   ├── modules/                # Extension modules (future)
│   ├── core.ts                 # Core search functionality
│   ├── cli.ts                  # CLI interface
│   ├── server.ts               # API server
│   └── index.ts                # Main entry point
├── config.json                 # Configuration file
├── package.json                # Package definition
├── tsconfig.json               # TypeScript configuration
└── README.md                   # This file
```

## Comparison with Python Version

This Bun.js/TypeScript implementation provides the same core functionality as the Python version:

✅ Search vulnerabilities by software name/version
✅ Search vulnerabilities by CVE/GHSA IDs  
✅ REST API for programmatic access
✅ CLI interface
✅ SQLite database support
✅ Configuration file support
✅ CVSS scoring and vulnerability metadata

**Differences:**
- API-only (no HTML frontend as per requirements)
- Uses Bun.js runtime instead of Python
- TypeScript for type safety
- Module system simplified (extensible but not yet fully implemented)
- Faster startup and lower memory footprint
- Native JSON handling

## License

MIT License - Same as the original Python implementation

## Credits

This is a TypeScript/Bun.js port of [search_vulns](https://github.com/ra1nb0rn/search_vulns) by Dustin Born (ra1nb0rn).
