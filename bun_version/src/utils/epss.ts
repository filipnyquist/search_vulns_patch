/**
 * EPSS (Exploit Prediction Scoring System) Integration
 * Adds exploitation probability data to vulnerabilities
 */

import type { Database } from 'bun:sqlite';
import type { Vulnerability } from '../types/vulnerability';

/**
 * Add EPSS scores to vulnerabilities
 * EPSS provides a probability (0-1) that a CVE will be exploited in the wild
 */
export function addEPSSScores(vulns: Record<string, Vulnerability>, vulnDb: Database): void {
  // Check if EPSS table exists
  try {
    const tableCheck = vulnDb.query(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='cve_epss'"
    );
    const tables = tableCheck.all();
    if (tables.length === 0) {
      // EPSS table doesn't exist, skip
      return;
    }
  } catch (error) {
    // Table doesn't exist or error checking, skip
    return;
  }

  for (const [vulnId, vuln] of Object.entries(vulns)) {
    const vulnCveIds = new Set<string>();
    
    // Collect all CVE IDs associated with this vulnerability
    if (vulnId.startsWith('CVE-')) {
      vulnCveIds.add(vulnId);
    }
    
    for (const alias of Object.keys(vuln.aliases)) {
      if (alias.startsWith('CVE-')) {
        vulnCveIds.add(alias);
      }
    }
    
    // In case of multiple CVEs mapped to one vulnerability, use highest EPSS
    let maxEpss = -1;
    let maxPercentile = -1;
    
    for (const cveId of vulnCveIds) {
      try {
        const stmt = vulnDb.query('SELECT epss, percentile FROM cve_epss WHERE cve_id = ?');
        const result = stmt.get(cveId) as any;
        
        if (result && result.epss !== null) {
          const epssValue = parseFloat(result.epss);
          const percentileValue = result.percentile !== null ? parseFloat(result.percentile) : -1;
          
          if (epssValue > maxEpss) {
            maxEpss = epssValue;
            maxPercentile = percentileValue;
          }
        }
      } catch (error) {
        // Error querying EPSS for this CVE, continue
      }
    }
    
    // Set EPSS score if found
    if (maxEpss !== -1) {
      // Format as percentage with 2 decimal places
      vuln.epss = (maxEpss * 100).toFixed(2) + '%';
      
      // Store percentile in misc if available
      if (maxPercentile !== -1) {
        vuln.misc['epss_percentile'] = (maxPercentile * 100).toFixed(1) + '%';
      }
    }
  }
}

/**
 * Get EPSS risk level based on score
 */
export function getEPSSRiskLevel(epssPercent: string): string {
  if (!epssPercent) return 'Unknown';
  
  const value = parseFloat(epssPercent.replace('%', ''));
  
  if (value >= 10) return 'Critical';
  if (value >= 5) return 'High';
  if (value >= 1) return 'Medium';
  if (value >= 0.1) return 'Low';
  return 'Very Low';
}
