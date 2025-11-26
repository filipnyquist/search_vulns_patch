/**
 * Equivalent CPEs Module
 * Handles loading and using CPE equivalences from:
 * - deprecated-cpes.json (official NVD deprecations)
 * - debian_equiv_cpes.json (Debian security tracker aliases)
 * - man_equiv_cpes.json (manually curated equivalences)
 */

import type { Database } from 'bun:sqlite';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// Resource file paths
const __dirname = dirname(fileURLToPath(import.meta.url));
const DEPRECATED_CPES_FILENAME = 'deprecated-cpes.json';
const DEPRECATED_CPES_FILE = join(__dirname, 'resources', DEPRECATED_CPES_FILENAME);
const DEBIAN_EQUIV_CPES_FILE = join(__dirname, 'resources', 'debian_equiv_cpes.json');
const MAN_EQUIVALENT_CPES_FILE = join(__dirname, 'resources', 'man_equiv_cpes.json');

const FULL_DEPRECATION_THRESHOLD = 0.16;

// Global cache for equivalent CPEs
let EQUIVALENT_CPES: Record<string, string[]> = {};
let EQUIVALENT_CPES_LOADED = false;

// Database result interfaces for type safety
interface ProductCpeCountResult {
  count: number;
}

/**
 * Get version sections from a version string
 * Similar to Python's CPEVersion.get_version_sections()
 */
function getVersionSections(versionStr: string): string[] {
  if (!versionStr || versionStr === '*' || versionStr === '-') {
    return [];
  }
  
  // Match sequences of letters with dots OR sequences of digits with dots
  const regex = /([a-zA-Z\.]+|[\d\.]+)/g;
  const matches = versionStr.match(regex);
  return matches || [];
}

/**
 * Load equivalent CPEs from various sources
 */
export async function loadEquivalentCpes(productDbCursor: Database): Promise<void> {
  if (EQUIVALENT_CPES_LOADED) {
    return;
  }

  const equivalentCpesDictsList: Array<Record<string, string[]>> = [];
  const deprecatedCpes: Record<string, string[]> = {};
  const deprecationsForProduct: Record<string, Record<string, string[]>> = {};

  // Try to load deprecated CPEs if available
  // Note: deprecated-cpes.json is downloaded during updates from NVD
  // For now, we'll handle it gracefully if it doesn't exist
  try {
    const deprecatedCpesFile = await Bun.file(DEPRECATED_CPES_FILE).text();
    const cpeDeprecationsRaw: Record<string, string[]> = JSON.parse(deprecatedCpesFile);

    // Group deprecations by product prefix
    for (const [cpe, deprecations] of Object.entries(cpeDeprecationsRaw)) {
      const productCpePrefix = cpe.split(':').slice(0, 5).join(':') + ':';
      
      if (!(productCpePrefix in deprecationsForProduct)) {
        deprecationsForProduct[productCpePrefix] = {};
      }
      deprecationsForProduct[productCpePrefix][cpe] = deprecations;
    }

    // Process deprecations
    for (const [productCpe, deprecations] of Object.entries(deprecationsForProduct)) {
      const productCpePrefix = productCpe.split(':').slice(0, 5).join(':') + ':';
      
      // Query product count from database
      try {
        const stmt = productDbCursor.query(
          'SELECT count FROM product_cpe_counts WHERE product_cpe_prefix = ?'
        );
        const result = stmt.get(productCpePrefix) as ProductCpeCountResult | null;
        
        if (result && result.count) {
          const productCpeCount = result.count;
          
          // Check for full deprecation of product
          if (Object.keys(deprecations).length >= productCpeCount * FULL_DEPRECATION_THRESHOLD) {
            const deprecationsPrefixes: string[] = [];
            
            for (const deprecatedByCpeList of Object.values(deprecations)) {
              for (const deprecatedByCpe of deprecatedByCpeList) {
                const deprecatedByCpePrefix = deprecatedByCpe.split(':').slice(0, 5).join(':') + ':';
                if (productCpePrefix !== deprecatedByCpePrefix) {
                  if (!deprecationsPrefixes.includes(deprecatedByCpePrefix)) {
                    deprecationsPrefixes.push(deprecatedByCpePrefix);
                  }
                }
              }
            }

            if (!(productCpePrefix in deprecatedCpes)) {
              deprecatedCpes[productCpePrefix] = deprecationsPrefixes;
            } else {
              deprecatedCpes[productCpePrefix] = Array.from(
                new Set([...deprecatedCpes[productCpePrefix], ...deprecationsPrefixes])
              );
            }

            for (const deprecatedByCpeShort of deprecationsPrefixes) {
              if (!(deprecatedByCpeShort in deprecatedCpes)) {
                deprecatedCpes[deprecatedByCpeShort] = [productCpePrefix];
              } else if (!deprecatedCpes[deprecatedByCpeShort].includes(productCpePrefix)) {
                deprecatedCpes[deprecatedByCpeShort].push(productCpePrefix);
              }
            }
          } else {
            // Only certain versions are deprecated
            for (const [fullProductCpe, deprecatedByCpeList] of Object.entries(deprecations)) {
              for (const deprecatedByCpe of deprecatedByCpeList) {
                if (!isCpeEqual(fullProductCpe, deprecatedByCpe)) {
                  if (!(fullProductCpe in deprecatedCpes)) {
                    deprecatedCpes[fullProductCpe] = [deprecatedByCpe];
                  } else if (!deprecatedCpes[fullProductCpe].includes(deprecatedByCpe)) {
                    deprecatedCpes[fullProductCpe].push(deprecatedByCpe);
                  }

                  if (!(deprecatedByCpe in deprecatedCpes)) {
                    deprecatedCpes[deprecatedByCpe] = [fullProductCpe];
                  } else if (!deprecatedCpes[deprecatedByCpe].includes(fullProductCpe)) {
                    deprecatedCpes[deprecatedByCpe].push(fullProductCpe);
                  }
                }
              }
            }
          }
        }
      } catch (error) {
        // Table might not exist, continue
      }
    }

    equivalentCpesDictsList.push(deprecatedCpes);
  } catch (error) {
    // deprecated-cpes.json doesn't exist yet, that's okay
    // Only log if there's an actual error (not just file not found)
    if (error instanceof Error && error.message.includes('ENOENT')) {
      // File doesn't exist - this is expected for fresh installations, silently skip
    } else {
      console.error('[equivalent_cpes] Error loading deprecated CPEs:', error instanceof Error ? error.message : error);
    }
  }

  // Load manually curated equivalent CPEs
  try {
    const manEquivCpesFile = await Bun.file(MAN_EQUIVALENT_CPES_FILE).text();
    const manualEquivalentCpes: Record<string, string[]> = JSON.parse(manEquivCpesFile);
    equivalentCpesDictsList.push(manualEquivalentCpes);
  } catch (error) {
    console.error('[equivalent_cpes] Error loading manual equivalent CPEs:', error instanceof Error ? error.message : error);
  }

  // Load Debian equivalent CPEs
  try {
    const debianEquivCpesFile = await Bun.file(DEBIAN_EQUIV_CPES_FILE).text();
    const debianEquivalentCpes: Record<string, string[]> = JSON.parse(debianEquivCpesFile);
    equivalentCpesDictsList.push(debianEquivalentCpes);
  } catch (error) {
    console.error('[equivalent_cpes] Error loading Debian equivalent CPEs:', error instanceof Error ? error.message : error);
  }

  // Unite information from different sources
  for (const equivalentCpesDict of equivalentCpesDictsList) {
    for (const [equivCpe, otherEquivCpes] of Object.entries(equivalentCpesDict)) {
      if (!(equivCpe in EQUIVALENT_CPES)) {
        EQUIVALENT_CPES[equivCpe] = [...otherEquivCpes];
      } else {
        EQUIVALENT_CPES[equivCpe] = [...EQUIVALENT_CPES[equivCpe], ...otherEquivCpes];
      }
    }
  }

  // Ensure bidirectional linking
  const cpeKeys = Object.keys(EQUIVALENT_CPES);
  for (const equivCpe of cpeKeys) {
    const otherEquivCpes = [...EQUIVALENT_CPES[equivCpe]];
    for (const otherEquivCpe of otherEquivCpes) {
      const otherRelevantEquivCpes = otherEquivCpes.map(cpe => 
        cpe === otherEquivCpe ? equivCpe : cpe
      );
      
      if (!(otherEquivCpe in EQUIVALENT_CPES)) {
        EQUIVALENT_CPES[otherEquivCpe] = otherRelevantEquivCpes;
      } else if (!EQUIVALENT_CPES[otherEquivCpe].includes(equivCpe)) {
        EQUIVALENT_CPES[otherEquivCpe] = [
          ...EQUIVALENT_CPES[otherEquivCpe],
          ...otherRelevantEquivCpes
        ];
      }
    }
  }

  EQUIVALENT_CPES_LOADED = true;
}

/**
 * Check if two CPEs are equal (ignoring wildcards)
 */
export function isCpeEqual(cpe1: string, cpe2: string): boolean {
  const parts1 = cpe1.split(':');
  const parts2 = cpe2.split(':');
  
  for (let i = 0; i < Math.min(parts1.length, parts2.length); i++) {
    if (parts1[i] !== parts2[i] && parts1[i] !== '*' && parts2[i] !== '*') {
      return false;
    }
  }
  
  return true;
}

/**
 * Get equivalent CPEs for a given CPE
 * Includes version transformations and equivalent product names
 */
export async function getEquivalentCpes(cpe: string, productDbCursor: Database): Promise<string[]> {
  // Ensure equivalent CPEs are loaded
  await loadEquivalentCpes(productDbCursor);

  const cpes: string[] = [cpe];
  const cpeSplit = cpe.split(':');
  const cpePrefix = cpeSplit.slice(0, 5).join(':') + ':';
  
  let cpeVersion = '*';
  let cpeSubversion = '*';
  
  if (cpeSplit.length > 5) {
    cpeVersion = cpeSplit[5];
  }
  if (cpeSplit.length > 6) {
    cpeSubversion = cpeSplit[6];
  }

  // If version part consists of more than one version parts, split into two CPE fields
  const cpeVersionSections = getVersionSections(cpeVersion);
  if (cpeVersionSections.length > 1 && ['*', '', '-'].includes(cpeSubversion)) {
    const newCpeSplit = [...cpeSplit];
    newCpeSplit[5] = cpeVersionSections.slice(0, -1).join('');
    newCpeSplit[6] = cpeVersionSections[cpeVersionSections.length - 1];
    cpes.push(newCpeSplit.join(':'));
  }

  // If CPE has subversion, create equivalent query with main version and subversion combined
  if (!['*', '', '-'].includes(cpeSubversion)) {
    const newCpeSplit = [...cpeSplit];
    newCpeSplit[5] = cpeVersion + '-' + cpeSubversion;
    newCpeSplit[6] = '*';
    cpes.push(newCpeSplit.join(':'));
  }

  // Get raw equivalent CPE prefixes, including transitively
  const rawEquivCpePrefixes = new Set<string>();

  function getAdditionalEquivCpes(cpePrefix: string): Set<string> {
    if (!(cpePrefix in EQUIVALENT_CPES)) {
      return new Set();
    }
    if (rawEquivCpePrefixes.has(cpePrefix)) {
      return new Set();
    }
    rawEquivCpePrefixes.add(cpePrefix);

    const additionalCpePrefixes = new Set<string>();
    for (const otherCpePrefix of EQUIVALENT_CPES[cpePrefix]) {
      if (!rawEquivCpePrefixes.has(otherCpePrefix)) {
        additionalCpePrefixes.add(otherCpePrefix);
        const nested = getAdditionalEquivCpes(otherCpePrefix);
        for (const item of nested) {
          additionalCpePrefixes.add(item);
        }
        rawEquivCpePrefixes.add(otherCpePrefix);
      }
    }

    return additionalCpePrefixes;
  }

  const equivCpesForPrefix = EQUIVALENT_CPES[cpePrefix] || [];
  for (const equivalentCpePrefix of equivCpesForPrefix) {
    if (!rawEquivCpePrefixes.has(equivalentCpePrefix)) {
      const additional = getAdditionalEquivCpes(equivalentCpePrefix);
      for (const item of additional) {
        rawEquivCpePrefixes.add(item);
      }
    }
  }

  // Generate proper equivalent CPEs with version info
  const equivCpes = [...cpes];
  for (const curCpe of cpes) {
    const curCpeSplit = curCpe.split(':');
    for (const equivalentCpe of rawEquivCpePrefixes) {
      const equivalentCpePrefix = equivalentCpe.split(':').slice(0, 5).join(':') + ':';
      if (equivalentCpe !== cpePrefix) {
        equivCpes.push(equivalentCpePrefix + curCpeSplit.slice(5).join(':'));
      }
    }
  }

  // Add CPE equivalences of full CPEs including version
  const addEquivCpes: string[] = [];
  for (const curCpe of equivCpes) {
    if (curCpe in EQUIVALENT_CPES) {
      addEquivCpes.push(...EQUIVALENT_CPES[curCpe]);
    }
  }
  equivCpes.push(...addEquivCpes);

  return equivCpes;
}
