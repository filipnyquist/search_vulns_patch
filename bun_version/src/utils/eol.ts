/**
 * End-of-Life (EOL) Data Integration
 * Determines if detected product versions are EOL or outdated
 */

import type { Database } from 'bun:sqlite';
import type { SearchVulnsResult } from '../types/vulnerability';
import { parseVersion, compareVersions } from './version';

export interface VersionStatus {
  status: 'current' | 'outdated' | 'eol' | 'N/A';
  latest: string;
  ref: string;
}

/**
 * Add EOL status to search results
 */
export function addEOLStatus(
  results: SearchVulnsResult,
  vulnDb: Database
): void {
  const productIds = results.product_ids;
  if (!productIds || !vulnDb) {
    return;
  }
  
  // Skip if another module has already provided version status
  if ('version_status' in results) {
    return;
  }
  
  // Check if EOL table exists
  try {
    const tableCheck = vulnDb.query(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='eol_date_data'"
    );
    const tables = tableCheck.all();
    if (tables.length === 0) {
      // EOL table doesn't exist, skip
      return;
    }
  } catch (error) {
    // Table doesn't exist or error checking, skip
    return;
  }
  
  let versionStatus: VersionStatus | null = null;
  
  for (const cpe of productIds.cpe || []) {
    if (versionStatus) {
      break;
    }
    
    const cpeSplit = cpe.split(':');
    const cpePrefix = cpeSplit.slice(0, 5).join(':') + ':';
    const queryVersionStr = cpeSplit[5] || '';
    const queryVersion = queryVersionStr && queryVersionStr !== '*' ? parseVersion(queryVersionStr) : null;
    
    // Get EOL releases for this product
    let eolReleases: any[] = [];
    try {
      const stmt = vulnDb.query(
        'SELECT eold_id, version_start, version_latest, eol_info FROM eol_date_data WHERE cpe_prefix = ? ORDER BY release_id DESC'
      );
      eolReleases = stmt.all(cpePrefix) as any[];
    } catch (error) {
      // Error querying EOL data, continue
      continue;
    }
    
    if (eolReleases.length === 0) {
      continue;
    }
    
    let latest = '';
    const now = new Date();
    
    for (let i = 0; i < eolReleases.length; i++) {
      const release = eolReleases[i];
      
      // Set up release information
      const eolRef = 'https://endoflife.date/' + release.eold_id;
      const releaseStart = parseVersion(release.version_start);
      const releaseEnd = parseVersion(release.version_latest);
      let releaseEol: Date | boolean = false;
      
      if (release.eol_info && release.eol_info !== 'true' && release.eol_info !== 'false') {
        try {
          releaseEol = new Date(release.eol_info);
        } catch {
          releaseEol = false;
        }
      } else if (release.eol_info === 'true') {
        releaseEol = true;
      }
      
      // Set latest version in first iteration
      if (!latest) {
        latest = release.version_latest;
      }
      
      if (!queryVersion) {
        // No version specified in query
        if (releaseEol && (releaseEol === true || now >= releaseEol)) {
          versionStatus = { status: 'eol', latest, ref: eolRef };
        } else {
          versionStatus = { status: 'N/A', latest, ref: eolRef };
        }
      } else {
        // Check query version status
        const versionComparison = compareVersions(queryVersion, releaseEnd);
        
        if (versionComparison >= 0) {
          // Query version is >= release end (latest in this release)
          if (releaseEol && (releaseEol === true || now >= releaseEol)) {
            versionStatus = { status: 'eol', latest, ref: eolRef };
          } else {
            versionStatus = { status: 'current', latest, ref: eolRef };
          }
        } else {
          // Check if version is in this release range or older
          const startComparison = compareVersions(queryVersion, releaseStart);
          
          if (
            (startComparison >= 0 && versionComparison < 0) || 
            (i === eolReleases.length - 1 && startComparison <= 0)
          ) {
            if (releaseEol && (releaseEol === true || now >= releaseEol)) {
              versionStatus = { status: 'eol', latest, ref: eolRef };
            } else {
              versionStatus = { status: 'outdated', latest, ref: eolRef };
            }
          }
        }
      }
      
      if (versionStatus) {
        break;
      }
    }
  }
  
  if (versionStatus) {
    results.version_status = versionStatus;
  }
}

/**
 * Format EOL status for display
 */
export function formatEOLStatus(status: VersionStatus | undefined): string {
  if (!status) {
    return '';
  }
  
  const statusText = {
    'current': '✓ Current version',
    'outdated': '⚠ Outdated (latest: ' + status.latest + ')',
    'eol': '✗ End-of-Life (latest: ' + status.latest + ')',
    'N/A': 'Version status unknown'
  }[status.status] || '';
  
  if (statusText && status.ref) {
    return `${statusText} - ${status.ref}`;
  }
  
  return statusText;
}
