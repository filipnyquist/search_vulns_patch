# Equivalent CPEs Implementation

## Overview

This implementation adds support for equivalent CPEs in the bun version of search_vulns, matching the functionality available in the Python version.

## What are Equivalent CPEs?

Equivalent CPEs are different CPE (Common Platform Enumeration) identifiers that refer to the same product. This happens for several reasons:

1. **Official NVD Deprecations**: The NVD occasionally deprecates CPE names and replaces them with new ones
2. **Debian Security Aliases**: The Debian security team maintains a list of equivalent CPE names  
3. **Manual Mappings**: Known equivalences curated by the maintainers (e.g., `redis:redis` → `redislabs:redis`)

## Files Used

### 1. `deprecated-cpes.json`
- **Source**: Downloaded from NVD during database updates
- **Purpose**: Contains official CPE deprecation information from the National Vulnerability Database
- **Format**: `{ "old_cpe": ["new_cpe1", "new_cpe2"], ... }`
- **Location**: `bun_version/src/utils/resources/deprecated-cpes.json` (created during update)
- **Status**: Optional - gracefully handled if not present

### 2. `debian_equiv_cpes.json`
- **Source**: Debian Security Tracker team
- **Purpose**: Contains CPE aliases from Debian's security database
- **Format**: `{ "cpe_prefix": ["equivalent_cpe1", "equivalent_cpe2"], ... }`
- **Location**: `bun_version/src/utils/resources/debian_equiv_cpes.json`
- **Status**: ✅ Included in repository

### 3. `man_equiv_cpes.json`  
- **Source**: Manually curated by maintainers
- **Purpose**: Contains known CPE equivalences (e.g., product rebranding, vendor changes)
- **Format**: `{ "cpe_prefix": ["equivalent_cpe1", "equivalent_cpe2"], ... }`
- **Location**: `bun_version/src/utils/resources/man_equiv_cpes.json`
- **Status**: ✅ Included in repository

### 4. `cveid_to_edbid.json`
- **Source**: Built from Exploit-DB data during updates
- **Purpose**: Maps CVE IDs to Exploit-DB IDs
- **Storage**: Stored in vulnerability database as `cve_edb` table
- **Status**: ✅ Already used by bun version (via database queries)

## Implementation Details

### Core Functions

#### `loadEquivalentCpes(productDbCursor: Database)`
Loads all equivalent CPE mappings from the three sources:
1. Attempts to load NVD deprecations (if available)
2. Loads manual equivalences
3. Loads Debian equivalences
4. Creates bidirectional mappings for transitive equivalence

#### `getEquivalentCpes(cpe: string, productDbCursor: Database)`
Returns all equivalent CPEs for a given CPE, including:
- The original CPE
- Version transformations (e.g., splitting `1.2.3` into `1.2` + `3`)
- Product/vendor equivalences from the loaded mappings
- Transitive equivalences (if A→B and B→C, then A→C)

#### `isCpeEqual(cpe1: string, cpe2: string)`
Compares two CPEs for equality, respecting wildcards (`*`)

### Integration

The equivalent CPEs functionality is integrated into the vulnerability search flow:

1. User queries with product name or CPE
2. CPE search finds the best matching CPE
3. **NEW**: `getEquivalentCpes()` expands to all equivalent CPEs
4. Vulnerability database is searched using ALL equivalent CPEs
5. More comprehensive results are returned

## Example

```typescript
// Query: "redis 6.0"
// CPE Search finds: "cpe:2.3:a:redis:redis:6.0:*:*:*:*:*:*:*"

// getEquivalentCpes() returns:
[
  "cpe:2.3:a:redis:redis:6.0:*:*:*:*:*:*:*",      // Original
  "cpe:2.3:a:redislabs:redis:6.0:*:*:*:*:*:*:*"   // Equivalent (from man_equiv_cpes.json)
]

// Vulnerabilities are found for BOTH CPEs
```

## Testing

Tests are located in `test/equivalent_cpes.test.ts`:

```bash
bun test test/equivalent_cpes.test.ts
```

## Differences from Python Version

1. **Async/Await**: Bun version uses async functions for file I/O
2. **Error Handling**: Gracefully handles missing `deprecated-cpes.json`
3. **File Paths**: Uses ES module `import.meta.url` for resource paths
4. **Database Access**: Uses Bun's SQLite API instead of Python's sqlite3

## Benefits

✅ **More Complete Vulnerability Detection**: Finds vulnerabilities listed under deprecated or alternative CPE names

✅ **Vendor Rebranding Support**: Handles cases where vendors change names (e.g., Redis → Redis Labs)

✅ **NVD Compatibility**: Respects official NVD CPE deprecations

✅ **Debian Integration**: Leverages Debian's extensive CPE alias database

## Future Work

- Download `deprecated-cpes.json` during database updates (currently handled by Python version)
- Periodic updates of `debian_equiv_cpes.json` and `man_equiv_cpes.json`
- Performance optimization for large equivalence sets
