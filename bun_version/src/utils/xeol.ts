/**
 * Xeol EOL Data Integration
 * Provides additional EOL data from xeol's dataset
 */

import type { Database } from 'bun:sqlite';
import { Database as BunDatabase } from 'bun:sqlite';
import type { SearchVulnsResult } from '../types/vulnerability';
import type { VersionStatus } from './eol';
import { parseVersion, compareVersions } from './version';
import { resolve, dirname } from 'path';
import { existsSync, mkdirSync } from 'fs';

const __dirname = dirname(new URL(import.meta.url).pathname);

export interface XeolConfig {
  enabled: boolean;
  databasePath?: string;
  autoDownload?: boolean;
  downloadUrl?: string;
}

export const DEFAULT_XEOL_CONFIG: XeolConfig = {
  enabled: false,
  databasePath: 'resources/xeol.db',
  autoDownload: false,
  downloadUrl: 'https://data.xeol.io/xeol/databases/listing.json', // Points to latest database listing
};

/**
 * Cache for CPE to product name mappings
 * This is populated dynamically as queries are made
 */
const CPE_TO_PRODUCT_NAME_CACHE: Record<string, string | null> = {};

/**
 * Normalize product name for fuzzy matching
 */
function normalizeProductName(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Extract product and vendor from CPE
 */
function extractCpeProductInfo(cpePrefix: string): { vendor: string; product: string } | null {
  // CPE format: cpe:2.3:a:vendor:product:
  const parts = cpePrefix.split(':');
  if (parts.length < 5) {
    return null;
  }
  
  return {
    vendor: parts[3] || '',
    product: parts[4] || '',
  };
}

/**
 * Try to find a matching xeol product name for a CPE prefix
 */
function findXeolProductForCpe(
  xeolDb: Database,
  cpePrefix: string
): string | null {
  // Check cache first
  if (cpePrefix in CPE_TO_PRODUCT_NAME_CACHE) {
    return CPE_TO_PRODUCT_NAME_CACHE[cpePrefix];
  }

  const cpeInfo = extractCpeProductInfo(cpePrefix);
  if (!cpeInfo) {
    CPE_TO_PRODUCT_NAME_CACHE[cpePrefix] = null;
    return null;
  }

  try {
    // First, try exact CPE match - xeol has products with CPE names
    // e.g., "cpe:2.3:a:apache:http_server" or "cpe:/a:apache:http_server"
    const cpe23Name = `cpe:2.3:a:${cpeInfo.vendor}:${cpeInfo.product}`;
    const cpe22Name = `cpe:/a:${cpeInfo.vendor}:${cpeInfo.product}`;
    
    const cpeQuery = xeolDb.query(
      `SELECT DISTINCT name FROM products 
       WHERE permalink LIKE '%pkg.xeol.io%' 
       AND (name = ? OR name = ?)
       LIMIT 1`
    );
    const cpeResult = cpeQuery.get(cpe23Name, cpe22Name) as any;
    
    if (cpeResult) {
      CPE_TO_PRODUCT_NAME_CACHE[cpePrefix] = cpeResult.name;
      return cpeResult.name;
    }

    // Build search terms from vendor and product
    const searchTerms: string[] = [];
    
    // Add product name variations
    searchTerms.push(cpeInfo.product);
    searchTerms.push(cpeInfo.product.replace(/_/g, ' '));
    searchTerms.push(cpeInfo.product.replace(/_/g, '-'));
    
    // Add vendor + product combinations
    if (cpeInfo.vendor && cpeInfo.vendor !== cpeInfo.product) {
      searchTerms.push(`${cpeInfo.vendor} ${cpeInfo.product}`);
      searchTerms.push(`${cpeInfo.vendor}-${cpeInfo.product}`);
      searchTerms.push(`${cpeInfo.vendor}_${cpeInfo.product}`);
    }

    // Common product name mappings
    const commonMappings: Record<string, string> = {
      'http_server': 'Apache HTTP Server',
      'node.js': 'Node.js',
      'nodejs': 'Node.js',
    };

    // Try exact matches first
    for (const term of searchTerms) {
      const mappedTerm = commonMappings[term.toLowerCase()] || term;
      
      const query = xeolDb.query(
        `SELECT DISTINCT name FROM products 
         WHERE permalink LIKE '%pkg.xeol.io%' 
         AND (name = ? OR LOWER(name) = ? OR LOWER(REPLACE(name, ' ', '')) = ?)
         LIMIT 1`
      );
      const result = query.get(
        mappedTerm,
        mappedTerm.toLowerCase(),
        normalizeProductName(mappedTerm).replace(/\s/g, '')
      ) as any;
      
      if (result) {
        CPE_TO_PRODUCT_NAME_CACHE[cpePrefix] = result.name;
        return result.name;
      }
    }

    // Try fuzzy matching with LIKE
    const normalizedProduct = normalizeProductName(cpeInfo.product);
    const normalizedVendor = normalizeProductName(cpeInfo.vendor);
    
    // Try product-based fuzzy match
    const fuzzyQuery = xeolDb.query(
      `SELECT DISTINCT name FROM products 
       WHERE permalink LIKE '%pkg.xeol.io%' 
       AND (
         LOWER(REPLACE(name, ' ', '')) LIKE ? 
         OR LOWER(REPLACE(name, '-', '')) LIKE ?
         OR LOWER(name) LIKE ?
       )
       LIMIT 1`
    );
    
    const fuzzyPatterns = [
      `%${normalizedProduct.replace(/\s/g, '')}%`,
      `%${normalizedProduct.replace(/\s/g, '')}%`,
      `%${normalizedProduct}%`,
    ];
    
    const fuzzyResult = fuzzyQuery.get(...fuzzyPatterns) as any;
    if (fuzzyResult) {
      CPE_TO_PRODUCT_NAME_CACHE[cpePrefix] = fuzzyResult.name;
      return fuzzyResult.name;
    }

    // No match found
    CPE_TO_PRODUCT_NAME_CACHE[cpePrefix] = null;
    return null;
  } catch (error) {
    console.error(`Error finding xeol product for CPE ${cpePrefix}: ${error}`);
    CPE_TO_PRODUCT_NAME_CACHE[cpePrefix] = null;
    return null;
  }
}

/**
 * Generate a user-friendly reference URL for a product
 */
function generateReferenceUrl(productName: string): string {
  // If product name looks like a CPE, try to extract a friendlier name
  if (productName.startsWith('cpe:2.3:')) {
    // Format: cpe:2.3:part:vendor:product:...
    const parts = productName.split(':');
    if (parts.length >= 5) {
      const product = parts[4] || '';
      // Use product name for URL
      return `https://endoflife.date/${product.replace(/_/g, '-')}`;
    }
  } else if (productName.startsWith('cpe:/')) {
    // Format: cpe:/part:vendor:product:...
    const parts = productName.split(':');
    if (parts.length >= 4) {
      const product = parts[3] || '';
      return `https://endoflife.date/${product.replace(/_/g, '-')}`;
    }
  }
  
  // For package names like "jquery/jquery", use the last part
  if (productName.includes('/')) {
    const parts = productName.split('/');
    return `https://endoflife.date/${parts[parts.length - 1]}`;
  }
  
  // For normal names, convert to URL-friendly format
  return `https://endoflife.date/${productName.toLowerCase().replace(/\s+/g, '-')}`;
}

/**
 * Get xeol database connection
 */
export function getXeolDatabaseConnection(config: XeolConfig): Database | null {
  if (!config.enabled || !config.databasePath) {
    return null;
  }

  let dbPath = config.databasePath;
  
  // Make path absolute if it's relative
  if (!dbPath.startsWith('/') && !dbPath.startsWith('~')) {
    dbPath = resolve(__dirname, '../../', dbPath);
  }

  if (!existsSync(dbPath)) {
    console.warn(`Xeol database not found at ${dbPath}`);
    return null;
  }

  try {
    const db = new BunDatabase(dbPath, { readonly: true });
    return db;
  } catch (error) {
    console.error(`Failed to open xeol database at ${dbPath}: ${error}`);
    return null;
  }
}

/**
 * Query xeol database for EOL information
 */
export function queryXeolEOL(
  xeolDb: Database,
  productName: string,
  version: string | null
): VersionStatus | null {
  try {
    // Query products by name
    const productQuery = xeolDb.query(
      `SELECT id, name, permalink FROM products 
       WHERE name = ? AND permalink LIKE '%pkg.xeol.io%'
       LIMIT 1`
    );
    const product = productQuery.get(productName) as any;
    
    if (!product) {
      return null;
    }

    // Get all release cycles for this product
    const cyclesQuery = xeolDb.query(
      `SELECT release_cycle, eol, eol_bool, latest_release, release_date, lts, support
       FROM cycles 
       WHERE product_id = ?
       ORDER BY release_date DESC`
    );
    const cycles = cyclesQuery.all(product.id) as any[];
    
    if (cycles.length === 0) {
      return null;
    }

    const now = new Date();
    let latest = '';
    let versionStatus: VersionStatus | null = null;
    
    // Find the latest version across all cycles
    // First check latest_release in each cycle, then fall back to release_cycle
    for (const cycle of cycles) {
      const candidateVersion = cycle.latest_release || cycle.release_cycle;
      if (candidateVersion && (!latest || candidateVersion > latest)) {
        latest = candidateVersion;
      }
    }
    
    // If no latest found, something is wrong with the data
    if (!latest) {
      return null;
    }
    
    // If no version specified, check if the latest is EOL
    if (!version || version === '*') {
      const latestCycle = cycles[0];
      const isEol = latestCycle.eol_bool === 1 || 
                    (latestCycle.eol && new Date(latestCycle.eol) <= now);
      
      return {
        status: isEol ? 'eol' : 'N/A',
        latest: latest,
        ref: generateReferenceUrl(product.name),
      };
    }

    // Parse query version
    const queryVersion = parseVersion(version);
    if (!queryVersion) {
      return null;
    }

    // Find matching cycle for the query version
    for (let i = 0; i < cycles.length; i++) {
      const cycle = cycles[i];
      const cycleVersion = parseVersion(cycle.release_cycle);
      const latestInCycle = cycle.latest_release 
        ? parseVersion(cycle.latest_release) 
        : cycleVersion;
      
      if (!cycleVersion) continue;

      const isEol = cycle.eol_bool === 1 || 
                    (cycle.eol && new Date(cycle.eol) <= now);

      // Check if query version matches this cycle
      if (compareVersions(queryVersion, cycleVersion) >= 0) {
        // Version is in this cycle or newer
        
        // Check if this version is actually newer than all known cycles
        // This indicates the database may be outdated
        const latestKnownVersion = parseVersion(latest);
        if (latestKnownVersion && compareVersions(queryVersion, latestKnownVersion) > 0) {
          // Query version is newer than anything in the database
          // Can't determine status - data might be outdated
          return null;
        }
        
        if (latestInCycle && compareVersions(queryVersion, latestInCycle) >= 0) {
          // Query version is the latest or newer in this cycle
          versionStatus = {
            status: isEol ? 'eol' : 'current',
            latest: latest,
            ref: generateReferenceUrl(product.name),
          };
          break;
        } else {
          // Query version is within this cycle but not the latest
          versionStatus = {
            status: isEol ? 'eol' : 'outdated',
            latest: latest,
            ref: generateReferenceUrl(product.name),
          };
          break;
        }
      } else if (i === cycles.length - 1) {
        // This is the oldest cycle and version is older
        versionStatus = {
          status: 'eol',
          latest: latest,
          ref: generateReferenceUrl(product.name),
        };
      }
    }

    return versionStatus;
  } catch (error) {
    console.error(`Error querying xeol database for ${productName}: ${error}`);
    return null;
  }
}

/**
 * Add xeol EOL status to search results
 */
export function addXeolEOLStatus(
  results: SearchVulnsResult,
  xeolDb: Database | null
): void {
  if (!xeolDb) {
    return;
  }

  const productIds = results.product_ids;
  if (!productIds) {
    return;
  }
  
  // Skip if EOL status already set by endoflife.date
  if ('version_status' in results) {
    return;
  }

  let versionStatus: VersionStatus | null = null;

  // Try to find xeol data for detected CPEs
  for (const cpe of productIds.cpe || []) {
    if (versionStatus) {
      break;
    }

    const cpeSplit = cpe.split(':');
    const cpePrefix = cpeSplit.slice(0, 5).join(':') + ':';
    const queryVersionStr = cpeSplit[5] || '';

    // Automatically find matching xeol product for this CPE
    const productName = findXeolProductForCpe(xeolDb, cpePrefix);
    if (!productName) {
      continue;
    }

    versionStatus = queryXeolEOL(xeolDb, productName, queryVersionStr);
  }

  if (versionStatus) {
    results.version_status = versionStatus;
  }
}

/**
 * Download and extract xeol database
 */
export async function downloadXeolDatabase(
  targetPath: string,
  downloadUrl?: string
): Promise<boolean> {
  try {
    // Get the latest database URL from listing
    const listingUrl = downloadUrl || DEFAULT_XEOL_CONFIG.downloadUrl!;
    console.log(`Fetching xeol database listing from ${listingUrl}`);
    
    const response = await fetch(listingUrl);
    if (!response.ok) {
      console.error(`Failed to fetch xeol database listing: ${response.statusText}`);
      return false;
    }

    const listing = await response.json() as any;
    const latestDb = listing.available?.['1']?.[0];
    
    if (!latestDb || !latestDb.url) {
      console.error('No xeol database URL found in listing');
      return false;
    }

    const dbUrl = latestDb.url;
    console.log(`Downloading xeol database from ${dbUrl}`);

    // Download the database
    const dbResponse = await fetch(dbUrl);
    if (!dbResponse.ok) {
      console.error(`Failed to download xeol database: ${dbResponse.statusText}`);
      return false;
    }

    const buffer = await dbResponse.arrayBuffer();
    const tempArchivePath = `${targetPath}.tar.xz`;
    
    // Ensure target directory exists
    const targetDir = dirname(targetPath);
    if (!existsSync(targetDir)) {
      mkdirSync(targetDir, { recursive: true });
    }

    // Save archive
    await Bun.write(tempArchivePath, buffer);

    // Extract using tar command
    const proc = Bun.spawn(['tar', '-xf', tempArchivePath, '-C', targetDir, 'xeol.db'], {
      stdout: 'pipe',
      stderr: 'pipe',
    });

    await proc.exited;

    if (proc.exitCode !== 0) {
      const stderr = await new Response(proc.stderr).text();
      console.error(`Failed to extract xeol database: ${stderr}`);
      return false;
    }

    // Move extracted file to target path
    const extractedPath = resolve(targetDir, 'xeol.db');
    if (existsSync(extractedPath) && extractedPath !== targetPath) {
      await Bun.write(targetPath, await Bun.file(extractedPath).arrayBuffer());
      // Clean up extracted file if different from target
      if (extractedPath !== targetPath) {
        await Bun.$`rm -f ${extractedPath}`;
      }
    }

    // Clean up archive
    await Bun.$`rm -f ${tempArchivePath}`;

    console.log(`Xeol database downloaded and extracted to ${targetPath}`);
    return true;
  } catch (error) {
    console.error(`Error downloading xeol database: ${error}`);
    return false;
  }
}
