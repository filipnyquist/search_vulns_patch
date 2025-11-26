# Xeol Dataset Integration

This document describes the integration of [xeol's EOL dataset](https://github.com/xeol-io/xeoldb) alongside the existing endoflife.date data source.

## Overview

The xeol dataset provides end-of-life (EOL) information for software products from multiple sources, including:
- endoflife.date data (via `pkg.xeol.io` permalinks)
- Package ecosystem data (npm, PyPI, Maven, etc.)
- Operating system distributions
- Container images

## How It Works

### Integration Architecture

The xeol integration works as a **fallback** to the existing endoflife.date integration:

1. **Primary Source**: The application first tries to get EOL data from the `eol_date_data` table in the vulnerability database
2. **Fallback Source**: If no EOL status is found, the application queries the xeol database
3. **Automatic Mapping**: CPE prefixes are automatically mapped to xeol product names using intelligent matching

### Automatic CPE Mapping

Instead of maintaining a hardcoded mapping between CPE prefixes and xeol products, the integration uses **automatic fuzzy matching**:

1. **Exact CPE Match**: First tries to match CPE-formatted product names in xeol (e.g., `cpe:2.3:a:apache:http_server`)
2. **Product Name Variations**: Tries variations of the product name (underscores, hyphens, spaces)
3. **Vendor + Product Combinations**: Tries combining vendor and product names
4. **Fuzzy Matching**: Falls back to LIKE-based fuzzy matching
5. **Caching**: Results are cached to improve performance

Example mappings:
- `cpe:2.3:a:apache:http_server:` → `Apache HTTP Server` or `cpe:2.3:a:apache:http_server`
- `cpe:2.3:a:jquery:jquery:` → `jquery/jquery`
- `cpe:2.3:o:alpine:alpine_linux:` → `alpine`

## Configuration

Add the following to your `config.json`:

```json
{
  "XEOL_DATABASE": {
    "ENABLED": true,
    "DATABASE_PATH": "resources/xeol.db",
    "AUTO_DOWNLOAD": false,
    "DOWNLOAD_URL": "https://data.xeol.io/xeol/databases/listing.json"
  }
}
```

### Configuration Options

- **ENABLED**: Set to `true` to enable xeol integration (default: `false`)
- **DATABASE_PATH**: Path to the xeol SQLite database (default: `resources/xeol.db`)
- **AUTO_DOWNLOAD**: Automatically download the database if not found (default: `false`)
- **DOWNLOAD_URL**: URL to fetch the latest xeol database listing (default: xeol's official listing)

## Downloading the Xeol Database

### Option 1: Using the Download Script

```bash
cd bun_version
bun src/utils/download_xeol.ts [target_path]
```

This will:
1. Fetch the latest database listing from xeol
2. Download the latest database archive
3. Extract it to the specified path (default: `resources/xeol.db`)

### Option 2: Manual Download

```bash
# Create resources directory
mkdir -p bun_version/resources

# Download the latest database
cd bun_version/resources
curl -L -o xeol-db.tar.xz "https://data.xeol.io/xeol/databases/xeol-db_v1_2025-11-26T00:00:45.459614Z.tar.xz"

# Extract
tar -xf xeol-db.tar.xz
rm xeol-db.tar.xz
```

**Note**: The database is updated regularly. Check the [xeol database listing](https://data.xeol.io/xeol/databases/listing.json) for the latest version.

## Database Structure

The xeol database contains the following tables:

### `products` Table
- `id`: Unique product identifier
- `name`: Product name (may be in various formats: human-readable, CPE, or package identifier)
- `permalink`: Product reference URL

### `cycles` Table
- `product_id`: References products table
- `release_cycle`: Version/release cycle identifier
- `eol`: End-of-life date (if applicable)
- `eol_bool`: Boolean EOL status
- `latest_release`: Latest version in this cycle
- `release_date`: Release date
- `lts`: Long-term support flag
- `support`: Support status flag

### `cpes` Table (Currently Empty)
- Intended for CPE mappings but currently not populated

### `purls` Table
- Package URL (purl) mappings for package ecosystems
- Links packages to products

## Usage Examples

### Querying EOL Status

The xeol integration is transparent to users. When enabled, it automatically provides EOL data:

```typescript
import { searchVulns } from './core';

const results = await searchVulns('Apache HTTP Server 2.2');

if (results.version_status) {
  console.log(`Status: ${results.version_status.status}`);
  console.log(`Latest: ${results.version_status.latest}`);
  console.log(`Reference: ${results.version_status.ref}`);
}
```

### CLI Usage

```bash
# With xeol enabled in config.json
bun src/cli.ts -q 'Apache HTTP Server 2.2'

# Output includes EOL status:
# [+] Apache HTTP Server 2.2 (cpe:2.3:a:apache:http_server:2.2:*:*:*:*:*:*:*)
# ✗ End-of-Life (latest: 2.4.62)
#   Info: https://endoflife.date/apache-http-server
```

## Data Sources

The xeol database consolidates EOL data from multiple sources:

1. **endoflife.date**: Products with `pkg.xeol.io` permalinks
2. **Package Ecosystems**: npm, PyPI, Maven, RubyGems, etc.
3. **Operating Systems**: Alpine, Debian, Ubuntu, etc.
4. **Container Images**: Docker official images, cloud provider images

## Benefits

### Complementary Coverage

- **endoflife.date**: Best for well-known software and platforms
- **xeol**: Additional coverage for package ecosystems and distributions

### Automatic Updates

The xeol database is updated regularly, providing fresh EOL data without manual maintenance.

### No Manual Mapping

The automatic CPE mapping eliminates the need to maintain hardcoded product mappings, making the integration more maintainable.

## Performance Considerations

1. **Caching**: CPE to product name mappings are cached in memory
2. **Fallback Only**: xeol is only queried if endoflife.date doesn't have data
3. **Read-Only**: The database is opened in read-only mode
4. **Database Size**: The xeol database is ~47MB (as of 2025-11-26)

## Limitations

1. **CPE Mapping Accuracy**: Automatic mapping may not always find the correct product
2. **Database Size**: The xeol database is relatively large compared to the focused endoflife.date table
3. **Update Frequency**: Database updates require manual download (unless AUTO_DOWNLOAD is enabled)

## Testing

Run the xeol integration tests:

```bash
cd bun_version
bun test test/xeol.test.ts
```

Tests verify:
- Database connection
- Product querying
- EOL status detection
- Fallback behavior (doesn't override endoflife.date)

## Troubleshooting

### Database Not Found

If you see "xeol database not found" warnings:
1. Download the database using the script or manually
2. Verify the `DATABASE_PATH` in config.json
3. Check file permissions

### No EOL Data

If xeol doesn't return EOL data:
1. Check that the product exists in the database
2. Verify CPE prefix is correct
3. Check mapping cache (may need to clear and restart)

### Performance Issues

If queries are slow:
1. Ensure database is on fast storage (SSD)
2. Check database file isn't corrupted
3. Consider disabling xeol if not needed

## Future Improvements

Potential enhancements:

1. **Automatic Database Updates**: Download and update the database automatically
2. **Improved Mapping**: Machine learning-based CPE to product mapping
3. **Merge Strategies**: Combine data from both sources instead of fallback-only
4. **Metrics**: Track mapping success rates and query performance
