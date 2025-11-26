# Summary: Using cveid_to_edbid.json and deprecated-cpes.json in Bun Version

## Issue
The bun version of search_vulns was not utilizing two important JSON files that the Python version uses:
1. `cveid_to_edbid.json` - Maps CVE IDs to Exploit-DB IDs
2. `deprecated-cpes.json` - Contains NVD CPE deprecation information

## Investigation Findings

### `cveid_to_edbid.json`
**Status**: ✅ Already implemented in bun version

- **Purpose**: Maps CVE IDs to their corresponding Exploit-DB identifiers
- **Python Implementation**: Created during updates and saved to `src/search_vulns/modules/exploit_db/cveid_to_edbid.json`
- **Bun Implementation**: Data is stored in the vulnerability database in the `cve_edb` table
- **Usage**: The bun version queries the `cve_edb` table in `src/core.ts` (lines 258-269) to fetch Exploit-DB IDs for CVEs
- **Conclusion**: This functionality was already present in the bun version via database queries

### `deprecated-cpes.json`
**Status**: ✅ Now implemented in bun version

- **Purpose**: Contains official NVD CPE deprecation information for finding equivalent CPEs
- **Python Implementation**: Downloaded during updates and used in `load_equivalent_cpes()` function
- **Bun Implementation**: Now implemented in `src/utils/equivalent_cpes.ts`

## Implementation Details

### New Files Created

1. **`src/utils/equivalent_cpes.ts`**
   - Core module for handling equivalent CPEs
   - Functions:
     - `loadEquivalentCpes()` - Loads from all three sources
     - `getEquivalentCpes()` - Expands a CPE to all its equivalents
     - `isCpeEqual()` - Compares CPEs with wildcard support

2. **`src/utils/resources/deprecated-cpes.json`**
   - Will be populated during database updates (currently handled by Python version)
   - Gracefully handled if not present

3. **`src/utils/resources/debian_equiv_cpes.json`**
   - Contains CPE aliases from Debian Security Tracker
   - Copied from Python version's resources

4. **`src/utils/resources/man_equiv_cpes.json`**
   - Manually curated CPE equivalences
   - Copied from Python version's resources

5. **`EQUIVALENT_CPES.md`**
   - Comprehensive documentation of the equivalent CPEs system

### Changes to Existing Files

1. **`src/core.ts`**
   - Added import for `getEquivalentCpes`
   - Modified CPE search flow to expand CPEs using equivalents
   - When not a product ID query, all equivalent CPEs are now used for vulnerability search

2. **`src/utils/version.ts`**
   - Fixed `parseVersion()` to handle non-string types (numbers, null, undefined)
   - Fixed `compareVersions()` to handle non-string types
   - Prevents `TypeError: versionStr.split is not a function` errors

3. **`README.md`**
   - Updated to highlight Equivalent CPEs as a feature

### Test Coverage

**`test/equivalent_cpes.test.ts`** - 14 tests covering:
- Version parsing with various input types (strings, numbers, null, undefined)
- Version comparison logic
- CPE equality checks
- Equivalent CPE expansion
- Loading behavior

All tests pass successfully.

## How It Works

### Flow Diagram

```
User Query: "redis 6.0"
    ↓
CPE Search finds: "cpe:2.3:a:redis:redis:6.0:*:*:*:*:*:*:*"
    ↓
getEquivalentCpes() expands to:
  - "cpe:2.3:a:redis:redis:6.0:*:*:*:*:*:*:*" (original)
  - "cpe:2.3:a:redislabs:redis:6.0:*:*:*:*:*:*:*" (from man_equiv_cpes.json)
    ↓
Search vulnerabilities for ALL equivalent CPEs
    ↓
Return comprehensive results
```

### Equivalent CPE Sources

1. **NVD Deprecations** (`deprecated-cpes.json`)
   - Official CPE deprecations from the National Vulnerability Database
   - Example: Old CPE deprecated in favor of new CPE

2. **Debian Aliases** (`debian_equiv_cpes.json`)
   - CPE aliases from Debian Security Tracker
   - Extensive database of equivalent product names

3. **Manual Equivalences** (`man_equiv_cpes.json`)
   - Curated by maintainers
   - Examples:
     - `redis:redis` → `redislabs:redis` (vendor rebranding)
     - `jquery:jquery_ui` → `jqueryui:jquery_ui`
     - Oracle product renamings

## Benefits

✅ **More Complete Vulnerability Detection**
- Finds vulnerabilities listed under deprecated CPE names
- Handles vendor rebranding (e.g., Redis → Redis Labs)
- Respects NVD CPE deprecations

✅ **Better Search Results**
- Users get comprehensive results even if they use old product names
- Equivalent products are automatically searched

✅ **Parity with Python Version**
- Bun version now has the same CPE equivalence functionality as Python version

## Bug Fix: Version Parsing

Fixed a critical bug where version parsing would fail with non-string types:

**Error**: `TypeError: versionStr.split is not a function`

**Root Cause**: EOL data or other sources sometimes provide versions as numbers instead of strings

**Solution**: 
- Updated `parseVersion()` and `compareVersions()` to accept `string | number | null | undefined`
- Convert to string internally before processing
- Handle null/undefined gracefully

## Testing Locally

The user can now run queries without errors:

```bash
bun run src/cli.ts -q "Apache 2.4.39"
bun run src/cli.ts -q "redis 6.0"
```

Both files are now properly utilized:
- ✅ `cveid_to_edbid.json` data via database queries
- ✅ `deprecated-cpes.json` and other equivalent CPE sources via new module

## Future Enhancements

- Automatic download of `deprecated-cpes.json` during bun version updates
- Periodic updates of Debian and manual equivalence files
- Performance optimization for large equivalence sets
