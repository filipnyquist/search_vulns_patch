import type { Database } from 'bun:sqlite';
import type { Config } from './types/config';
import type { SearchVulnsResult } from './types/vulnerability';
import { Vulnerability, MatchReason, compareMatchReasons } from './types/vulnerability';
import { getDatabaseConnection } from './utils/database';
import {
  isVersionInRange,
  cpeMatchesPrefix,
  getCpeVersion,
} from './utils/version';
import { search_cpes, MATCH_CPE_23_RE } from './utils/cpe_search';
import { addEPSSScores } from './utils/epss';
import { addEOLStatus } from './utils/eol';
import { getEquivalentCpes } from './utils/equivalent_cpes';

/**
 * Merge vulnerabilities from different modules, combining aliases and deduplicating
 */
export function mergeModuleVulns(
  allModuleVulns: Record<string, Record<string, Vulnerability>>,
  modulesDataPreference: string[]
): Record<string, Vulnerability> {
  const mergedVulns: Record<string, Vulnerability> = {};
  const mergeOrder = [
    ...modulesDataPreference,
    ...Object.keys(allModuleVulns).filter((k) => !modulesDataPreference.includes(k)).sort(),
  ];

  for (const moduleId of mergeOrder) {
    if (!(moduleId in allModuleVulns)) {
      continue;
    }

    const vulns = allModuleVulns[moduleId];
    const trackedAliasMap: Record<string, string[]> = {};

    for (const [vulnId, vuln] of Object.entries(vulns)) {
      let trackedAlias: string | null = null;

      // Check if this vulnerability ID is already tracked
      for (const alias of Object.keys(vuln.aliases)) {
        if (alias in mergedVulns) {
          trackedAlias = alias;
          break;
        }
        if (alias in trackedAliasMap) {
          trackedAlias = trackedAliasMap[alias][0];
          break;
        }

        // Check if current vulnerability was already processed via an alias
        for (const [mergedVulnId, mergedVuln] of Object.entries(mergedVulns)) {
          if (alias in mergedVuln.aliases) {
            trackedAlias = mergedVulnId;
            break;
          }
        }
        if (trackedAlias) break;
      }

      if (!trackedAlias) {
        mergedVulns[vulnId] = vuln;
        for (const alias of Object.keys(vuln.aliases)) {
          if (!(alias in trackedAliasMap)) {
            trackedAliasMap[alias] = [];
          }
          trackedAliasMap[alias].push(alias);
        }
      } else {
        const oldVulnId = mergedVulns[trackedAlias].id;
        mergedVulns[trackedAlias].mergeWithVulnerability(vuln);
        const newVulnId = mergedVulns[trackedAlias].id;

        // Other vulnerability had higher match_reason and vuln attributes were changed
        if (oldVulnId !== newVulnId) {
          mergedVulns[newVulnId] = mergedVulns[oldVulnId];
          delete mergedVulns[oldVulnId];
          if (oldVulnId in trackedAliasMap) {
            trackedAliasMap[newVulnId] = trackedAliasMap[oldVulnId];
            delete trackedAliasMap[oldVulnId];
          } else {
            trackedAliasMap[newVulnId] = Object.keys(mergedVulns[newVulnId].aliases);
          }
        }
        trackedAliasMap[newVulnId] = Object.keys(mergedVulns[newVulnId].aliases);
      }
    }
  }

  return mergedVulns;
}

/**
 * Main search function for vulnerabilities
 */
export async function searchVulns(
  query: string,
  knownProductIds: Record<string, string[]> | null = null,
  vulnDbConnection: Database | null = null,
  productDbConnection: Database | null = null,
  isProductIdQuery: boolean = false,
  ignoreGeneralProductVulns: boolean = false,
  includeSingleVersionVulns: boolean = false,
  includePatched: boolean = false,
  config: Config | null = null,
  skipVulnSearch: boolean = false
): Promise<SearchVulnsResult> {
  // Load config if not provided
  if (!config) {
    const { loadConfig } = await import('../utils/config.ts');
    config = await loadConfig();
  }

  // Create DB connections if not provided
  let closeVulnDbAfter = false;
  let closeProductDbAfter = false;
  let vulnDb = vulnDbConnection;
  let productDb = productDbConnection;

  if (!skipVulnSearch && !vulnDb) {
    vulnDb = getDatabaseConnection(config.VULN_DATABASE);
    closeVulnDbAfter = true;
  }
  if (!productDb) {
    productDb = getDatabaseConnection(config.PRODUCT_DATABASE);
    closeProductDbAfter = true;
  }

  const queryProcessed = query.trim();
  const extraParams: Record<string, any> = {};

  // Initialize result structure
  const productIds: Record<string, string[]> = knownProductIds
    ? { ...knownProductIds }
    : { cpe: [] };
  const potProductIds: Record<string, any[]> = {};
  
  // Perform CPE search if not already a CPE and no product IDs provided
  if (!knownProductIds && productDb) {
    if (!MATCH_CPE_23_RE.test(queryProcessed)) {
      // Search for CPE matches using product name/version
      const cpeSearchResult = await search_cpes(
        queryProcessed,
        productDb,
        config.CPE_SEARCH_COUNT || 10,
        config.CPE_SEARCH_THRESHOLD || 0.68,
        config
      );
      
      if (cpeSearchResult.cpes && cpeSearchResult.cpes.length > 0) {
        const baseCpe = cpeSearchResult.cpes[0][0];
        
        // Get equivalent CPEs if not a product ID query
        if (isProductIdQuery) {
          productIds.cpe = [baseCpe];
        } else {
          productIds.cpe = await getEquivalentCpes(baseCpe, productDb);
        }
      }
      
      if (cpeSearchResult.pot_cpes && cpeSearchResult.pot_cpes.length > 0) {
        potProductIds.cpe = cpeSearchResult.pot_cpes;
      }
    } else {
      // Query is already a CPE string
      // Normalize CPE if needed
      let cpe = queryProcessed;
      const cpeParts = cpe.split(':');
      if (cpeParts.length < 13) {
        cpe = cpe + ':*'.repeat(13 - cpeParts.length);
      }
      
      // Get equivalent CPEs if not a product ID query
      if (isProductIdQuery) {
        productIds.cpe = [cpe];
      } else {
        productIds.cpe = await getEquivalentCpes(cpe, productDb);
      }
    }
  }

  let vulns: Record<string, Vulnerability> = {};

  // Basic vulnerability search (simplified - in full implementation, modules would handle this)
  if (!skipVulnSearch && vulnDb) {
    vulns = await searchVulnsBasic(queryProcessed, productIds, vulnDb, config, extraParams);
    
    // Add exploit information
    addExploitInfo(vulns, vulnDb);
    
    // Add EPSS scores (exploitation probability)
    addEPSSScores(vulns, vulnDb);

    // Filter vulnerabilities based on options
    for (const vulnId of Object.keys(vulns)) {
      if (
        ignoreGeneralProductVulns &&
        vulns[vulnId].matchReason === MatchReason.GENERAL_PRODUCT_UNCERTAIN
      ) {
        delete vulns[vulnId];
        continue;
      }
      if (
        !includeSingleVersionVulns &&
        vulns[vulnId].matchReason === MatchReason.SINGLE_HIGHER_VERSION
      ) {
        delete vulns[vulnId];
      }
    }
  }

  // Remove patched vulnerabilities if requested
  if (!includePatched) {
    const delVulnIds: string[] = [];
    for (const [vulnId, vuln] of Object.entries(vulns)) {
      if (vuln.isPatched()) {
        delVulnIds.push(vulnId);
      }
    }
    for (const vulnId of delVulnIds) {
      delete vulns[vulnId];
    }
  }

  // Build result object
  const result: SearchVulnsResult = {
    product_ids: productIds,
    vulns: vulns,
    pot_product_ids: potProductIds,
  };
  
  // Add EOL (End-of-Life) status for detected products
  if (vulnDb) {
    addEOLStatus(result, vulnDb);
  }

  // Close DB connections if we opened them
  if (closeVulnDbAfter && vulnDb) {
    vulnDb.close();
  }
  if (closeProductDbAfter && productDb) {
    productDb.close();
  }

  return result;
}

/**
 * Add exploit information to vulnerabilities
 */
function addExploitInfo(vulns: Record<string, Vulnerability>, vulnDb: Database): void {
  for (const [vulnId, vuln] of Object.entries(vulns)) {
    // Check for CVE IDs in the vulnerability and its aliases
    const cveIds = new Set<string>();
    if (vulnId.startsWith('CVE-')) {
      cveIds.add(vulnId);
    }
    for (const alias of Object.keys(vuln.aliases)) {
      if (alias.startsWith('CVE-')) {
        cveIds.add(alias);
      }
    }
    
    // Fetch exploits for each CVE from different sources
    for (const cveId of cveIds) {
      // NVD exploit references
      try {
        const stmt = vulnDb.query('SELECT exploit_ref FROM nvd_exploits_refs_view WHERE cve_id = ?');
        const exploits = stmt.all(cveId) as any[];
        for (const exploit of exploits) {
          vuln.exploits.add(exploit.exploit_ref);
        }
      } catch (error) {
        // Silently ignore if view doesn't exist
      }
      
      // Exploit-DB
      try {
        const stmt = vulnDb.query('SELECT edb_ids FROM cve_edb WHERE cve_id = ?');
        const edbResult = stmt.get(cveId) as any;
        if (edbResult && edbResult.edb_ids) {
          const edbIds = edbResult.edb_ids.split(',');
          for (const edbId of edbIds) {
            vuln.exploits.add(`https://www.exploit-db.com/exploits/${edbId.trim()}`);
          }
        }
      } catch (error) {
        // Silently ignore
      }
      
      // PoC in GitHub
      try {
        const stmt = vulnDb.query('SELECT reference FROM poc_in_github WHERE cve_id = ?');
        const pocs = stmt.all(cveId) as any[];
        for (const poc of pocs) {
          if (poc.reference) {
            vuln.exploits.add(poc.reference);
          }
        }
      } catch (error) {
        // Silently ignore
      }
    }
  }
}

/**
 * Basic vulnerability search (placeholder for module-based implementation)
 */
async function searchVulnsBasic(
  query: string,
  productIds: Record<string, string[]>,
  vulnDb: Database,
  config: Config,
  extraParams: Record<string, any>
): Promise<Record<string, Vulnerability>> {
  const vulns: Record<string, Vulnerability> = {};

  // First, check if we have CPEs to search for
  if (productIds.cpe && productIds.cpe.length > 0) {
    for (const cpe of productIds.cpe) {
      try {
        const cpePrefix = cpe.split(':').slice(0, 5).join(':') + ':';
        const queryVersion = getCpeVersion(cpe);
        
        // Search in NVD CPE mappings with version range support
        const stmt = vulnDb.query(
          `SELECT DISTINCT n.cve_id, n.description, n.published, n.last_modified, 
           n.cvss_version, n.base_score, n.vector, n.cisa_known_exploited,
           nc.cpe, nc.cpe_version_start, nc.is_cpe_version_start_including,
           nc.cpe_version_end, nc.is_cpe_version_end_including
           FROM nvd n 
           JOIN nvd_cpe nc ON n.cve_id = nc.cve_id 
           WHERE nc.cpe LIKE ?`
        );
        const rows = stmt.all(cpePrefix + '%') as any[];

        for (const row of rows) {
          // Check if CPE prefix matches
          if (!cpeMatchesPrefix(cpe, row.cpe)) {
            continue;
          }
          
          // Determine match reason based on version matching
          let matchReason = MatchReason.PRODUCT_MATCH;
          let matches = false;
          
          const vulnCpeVersion = getCpeVersion(row.cpe);
          const hasVersionRange = row.cpe_version_start || row.cpe_version_end;
          
          if (queryVersion && queryVersion !== '*') {
            if (hasVersionRange) {
              // Check if query version is in the vulnerability's version range
              matches = isVersionInRange(
                queryVersion,
                row.cpe_version_start,
                row.is_cpe_version_start_including === 1,
                row.cpe_version_end,
                row.is_cpe_version_end_including === 1
              );
              if (matches) {
                matchReason = MatchReason.VERSION_IN_RANGE;
              }
            } else if (vulnCpeVersion === '*') {
              // General product vulnerability (no specific version)
              matches = true;
              matchReason = MatchReason.GENERAL_PRODUCT_UNCERTAIN;
            } else if (vulnCpeVersion === queryVersion) {
              // Exact version match
              matches = true;
              matchReason = MatchReason.PRODUCT_MATCH;
            }
          } else if (!queryVersion || queryVersion === '*') {
            // Query has no version, match general vulnerabilities
            if (vulnCpeVersion === '*') {
              matches = true;
              matchReason = MatchReason.GENERAL_PRODUCT_OK;
            }
          }
          
          if (matches) {
            const vuln = new Vulnerability({
              id: row.cve_id,
              matchReason: matchReason,
              matchSources: ['nvd'],
              description: row.description || '',
              published: row.published || '',
              modified: row.last_modified || '',
              cvssVer: row.cvss_version || '',
              cvss: row.base_score?.toString() || '-1.0',
              cvssVec: row.vector || '',
              cisaKnownExploited: row.cisa_known_exploited === 1,
              href: `https://nvd.nist.gov/vuln/detail/${row.cve_id}`,
            });
            
            // Merge if already exists
            if (vulns[vuln.id]) {
              vulns[vuln.id].mergeWithVulnerability(vuln);
            } else {
              vulns[vuln.id] = vuln;
            }
          }
        }
      } catch (error) {
        console.error(`Error searching for CPE ${cpe}:`, error);
      }
    }
  }

  // Split query by commas to handle multiple IDs
  const queries = query.split(',').map(q => q.trim());
  
  for (const singleQuery of queries) {
    // Check if query is a vulnerability ID (CVE, GHSA, etc.)
    const cvePattern = /CVE-\d{4}-\d+/i;
    const ghsaPattern = /GHSA-[a-z0-9-]+/i;
    
    const cveMatch = singleQuery.match(cvePattern);
    const ghsaMatch = singleQuery.match(ghsaPattern);

    // Search for CVE in NVD table
    if (cveMatch) {
      const cveId = cveMatch[0];
      try {
        const stmt = vulnDb.query(
          'SELECT * FROM nvd WHERE cve_id = ?'
        );
        const row = stmt.get(cveId.toUpperCase()) as any;

        if (row) {
          const vuln = new Vulnerability({
            id: row.cve_id || cveId.toUpperCase(),
            matchReason: MatchReason.VULN_ID,
            matchSources: ['nvd'],
            description: row.description || '',
            published: row.published || '',
            modified: row.last_modified || '',
            cvssVer: row.cvss_version || '',
            cvss: row.base_score?.toString() || '-1.0',
            cvssVec: row.vector || '',
            cisaKnownExploited: row.cisa_known_exploited === 1,
            href: `https://nvd.nist.gov/vuln/detail/${cveId.toUpperCase()}`,
          });
          vulns[vuln.id] = vuln;
        }
      } catch (error) {
        console.error(`Error searching for CVE ${cveId}:`, error);
      }
    }

    // Search for GHSA ID in GHSA table
    if (ghsaMatch) {
      const ghsaId = ghsaMatch[0];
      try {
        const stmt = vulnDb.query(
          'SELECT * FROM ghsa WHERE ghsa_id = ?'
        );
        // GHSA IDs are stored in original case (lowercase letters)
        const row = stmt.get(ghsaId) as any;

        if (row) {
          const vuln = new Vulnerability({
            id: row.ghsa_id || ghsaId,
            matchReason: MatchReason.VULN_ID,
            matchSources: ['ghsa'],
            description: row.description || '',
            published: row.published || '',
            modified: row.last_modified || '',
            cvssVer: row.cvss_version || '',
            cvss: row.base_score?.toString() || '-1.0',
            cvssVec: row.vector || '',
            cisaKnownExploited: false,
            href: `https://github.com/advisories/${ghsaId.toUpperCase()}`,
          });
          vulns[vuln.id] = vuln;
        }
      } catch (error) {
        console.error(`Error searching for GHSA ${ghsaId}:`, error);
      }
    }
  }

  return vulns;
}

/**
 * Serialize vulnerabilities in result for JSON output
 */
export function serializeVulnsInResult(result: SearchVulnsResult): void {
  const serialVulns: Record<string, any> = {};
  for (const [vulnId, vuln] of Object.entries(result.vulns)) {
    serialVulns[vulnId] = vuln.toDict();
  }
  (result as any).vulns = serialVulns;
}

/**
 * Get version of the package
 */
export function getVersion(): string {
  return '0.8.2';
}
