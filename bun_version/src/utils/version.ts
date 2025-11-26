/**
 * Simple version comparison utility
 * Based on Python's CPEVersion class but simplified
 */

/**
 * Parse a version string into comparable parts
 */
export function parseVersion(versionStr: string): (string | number)[] {
  if (!versionStr || versionStr === '*') {
    return [];
  }

  // Split on dots, dashes, underscores
  const parts = versionStr.split(/[.\-_]/);
  
  return parts.map(part => {
    // Try to parse as number
    const num = parseInt(part, 10);
    if (!isNaN(num) && num.toString() === part) {
      return num;
    }
    return part.toLowerCase();
  });
}

/**
 * Compare two versions
 * Returns: -1 if a < b, 0 if a == b, 1 if a > b
 */
export function compareVersions(a: string, b: string): number {
  const aParts = parseVersion(a);
  const bParts = parseVersion(b);
  
  const maxLen = Math.max(aParts.length, bParts.length);
  
  for (let i = 0; i < maxLen; i++) {
    const aPart = i < aParts.length ? aParts[i] : 0;
    const bPart = i < bParts.length ? bParts[i] : 0;
    
    // Handle numeric comparison
    if (typeof aPart === 'number' && typeof bPart === 'number') {
      if (aPart < bPart) return -1;
      if (aPart > bPart) return 1;
      continue;
    }
    
    // Handle string comparison
    const aStr = String(aPart);
    const bStr = String(bPart);
    
    if (aStr < bStr) return -1;
    if (aStr > bStr) return 1;
  }
  
  return 0;
}

/**
 * Check if version is in range
 */
export function isVersionInRange(
  version: string,
  startVersion: string | null,
  startInclusive: boolean,
  endVersion: string | null,
  endInclusive: boolean
): boolean {
  if (!version || version === '*') {
    return false;
  }
  
  // Check start version
  if (startVersion && startVersion !== '*') {
    const cmp = compareVersions(version, startVersion);
    if (startInclusive) {
      if (cmp < 0) return false;
    } else {
      if (cmp <= 0) return false;
    }
  }
  
  // Check end version
  if (endVersion && endVersion !== '*') {
    const cmp = compareVersions(version, endVersion);
    if (endInclusive) {
      if (cmp > 0) return false;
    } else {
      if (cmp >= 0) return false;
    }
  }
  
  return true;
}

/**
 * Check if a CPE matches based on its prefix (vendor:product)
 */
export function cpeMatchesPrefix(queryCpe: string, vulnCpe: string): boolean {
  const queryParts = queryCpe.split(':');
  const vulnParts = vulnCpe.split(':');
  
  // Match up to vendor:product (indices 0-4)
  for (let i = 0; i < 5 && i < queryParts.length && i < vulnParts.length; i++) {
    if (queryParts[i] !== vulnParts[i] && vulnParts[i] !== '*') {
      return false;
    }
  }
  
  return true;
}

/**
 * Extract version from CPE string
 */
export function getCpeVersion(cpe: string): string {
  const parts = cpe.split(':');
  return parts.length > 5 ? parts[5] : '*';
}
