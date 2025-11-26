import type { Database } from 'bun:sqlite';
import type { Config } from './types/config';
import type { SearchVulnsResult } from './types/vulnerability';
import { Vulnerability, MatchReason, compareMatchReasons } from './types/vulnerability';
import { getDatabaseConnection } from './utils/database';

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

  // TODO: Load and call modules for preprocessing, product ID search, vuln search, etc.
  // For now, implement basic functionality

  // Initialize result structure
  const productIds: Record<string, string[]> = knownProductIds
    ? { ...knownProductIds }
    : { cpe: [] };
  const potProductIds: Record<string, any[]> = {};
  let vulns: Record<string, Vulnerability> = {};

  // Basic vulnerability search (simplified - in full implementation, modules would handle this)
  if (!skipVulnSearch && vulnDb) {
    // This is a placeholder for module-based search
    // In the Python version, modules like nvd.search_vulns_nvd handle the actual search
    vulns = await searchVulnsBasic(queryProcessed, productIds, vulnDb, config, extraParams);

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

  // Close DB connections if we opened them
  if (closeVulnDbAfter && vulnDb) {
    vulnDb.close();
  }
  if (closeProductDbAfter && productDb) {
    productDb.close();
  }

  return {
    product_ids: productIds,
    vulns: vulns,
    pot_product_ids: potProductIds,
  };
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
