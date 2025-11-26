/**
 * Search Vulns - Bun.js/TypeScript implementation
 * Main entry point
 */

export { searchVulns, serializeVulnsInResult, getVersion } from './core.ts';
export { loadConfig } from './utils/config.ts';
export { getDatabaseConnection } from './utils/database.ts';
export { Vulnerability, MatchReason } from './types/vulnerability.ts';
export type { SearchVulnsResult } from './types/vulnerability.ts';
export type { Config } from './types/config.ts';
