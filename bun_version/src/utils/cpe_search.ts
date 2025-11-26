/**
 * CPE Search Module - Complete TypeScript Port
 * Exact translation of cpe_search Python module to TypeScript/Bun
 * 
 * Original: https://github.com/ra1nb0rn/cpe_search
 * Author: Dustin Born (ra1nb0rn)
 * TypeScript Port for Bun.js
 */

import type { Database } from 'bun:sqlite';

// Constants - matching Python implementation exactly
const TEXT_TO_VECTOR_RE = /[\w+\.]+/g;
const CPE_TERM_WEIGHT_EXP_FACTOR = -0.08;
const QUERY_TERM_WEIGHT_EXP_FACTOR = -0.25;
const VERSION_MATCH_ZE_RE = /\b([\d]+\.?){1,4}\b/;
const VERSION_MATCH_CPE_CREATION_RE = /\b((\d[\da-zA-Z\.]{0,6})([\+\-\.\_\~ ][\da-zA-Z\.]+){0,4})[^\w\n]*$/;
const VERSION_SPLIT_DIFF_CHARSETS_RE = /(?<=\d)(?=[^\d.])/;
export const MATCH_CPE_23_RE = /cpe:2\.3:[aoh](:[^:]+){2,10}/;
const CPE_SEARCH_THRESHOLD_ALT = 0.25;
const ALT_QUERY_MAXSPLIT = 1;
const CPE_CREATION_DEL_SYMBOLS_RE = /[\]"\|{>)/`<#},\[\:(=;^'%]/g;

const POPULAR_QUERY_CORRECTIONS: Record<string, string> = {
  'flask': 'palletsprojects',
  'keycloak': 'redhat red hat',
  'rabbitmq': 'vmware',
  'bootstrap': 'getbootstrap',
  'kotlin': 'jetbrains',
  'spring boot': 'vmware',
  'debian': 'linux',
  'ansible': 'redhat',
  'twig': 'symfony',
  'proxmox ve': 'virtual environment',
  'nextjs': 'vercel',
  'next.js': 'vercel',
  'ubuntu': 'linux',
  'symfony': 'sensiolabs',
  'electron': 'electronjs',
  'microsoft exchange': 'server',
};

const QUERY_ABBREVIATIONS: Record<string, [string[], string]> = {
  'adc': [['citrix'], 'application delivery controller'],
  'omsa': [['dell'], 'openmanage server administrator'],
  'cdk': [['amazon', 'aws'], 'aws cdk cloud development kit'],
  'srm': [['vmware'], 'site recovery manager'],
  'paloaltonetworks': [[], 'palo alto networks'],
  'palo alto networks': [[], 'paloaltonetworks'],
  'trend micro': [[], 'trendmicro'],
  'ds': [['trend', 'micro'], 'deep security'],
  'ms': [[], 'microsoft'],
  'dsa': [['trend', 'micro'], 'deep security agent'],
  'dsm': [['trend', 'micro'], 'deep security manager'],
  'asa': [['cisco'], 'adaptive security appliance'],
};

const TF_IDF_DEDUPLICATION_KEYWORDS: Record<string, number> = {
  'apache': 1,
  'flask': 1,
};

interface CPESearchConfig {
  CPE_SEARCH_COUNT?: number;
  CPE_SEARCH_THRESHOLD?: number;
}

interface CPESearchResult {
  cpes: Array<[string, number]>;
  pot_cpes: Array<[string, number]>;
}

interface QueryInfo {
  tf: Record<string, number>;
  abs: number;
}

/**
 * Get possible version strings from a query
 */
function getPossibleVersionsInQuery(query: string): string[] {
  const versionParts: string[] = [];
  const versionStrMatch = query.match(VERSION_MATCH_CPE_CREATION_RE);
  
  if (versionStrMatch) {
    const fullVersionStr = versionStrMatch[1].trim();
    versionParts.push(fullVersionStr);
    versionParts.push(...fullVersionStr.split(/[\+\-\_\~ ]/));
    
    // Remove first element in case of duplicate
    if (versionParts.length > 1 && versionParts[0] === versionParts[1]) {
      versionParts.shift();
    }
  }
  
  return versionParts;
}

/**
 * Generate alternative queries to improve retrieval
 */
function getAlternativeQueries(initQueries: string[]): Record<string, string[]> {
  const altQueriesMapping: Record<string, string[]> = {};
  
  for (const query of initQueries) {
    altQueriesMapping[query] = [];
    
    // Replace 'httpd' with 'http'
    if (query.includes('httpd')) {
      const altQuery = query.replace(/httpd/g, 'http');
      altQueriesMapping[query].push(altQuery);
    }
    
    // Check for "simple" abbreviations
    let altQueryAllReplaced = query;
    for (const [abbreviation, [requiredKeywords, replacement]] of Object.entries(QUERY_ABBREVIATIONS)) {
      if (requiredKeywords.length === 0 || requiredKeywords.some(kw => query.includes(kw))) {
        if (query.startsWith(abbreviation) || 
            query.endsWith(abbreviation) || 
            query.includes(` ${abbreviation} `)) {
          altQueriesMapping[query].push(query.replace(new RegExp(abbreviation, 'g'), ` ${replacement} `));
          altQueryAllReplaced = altQueryAllReplaced.replace(new RegExp(abbreviation, 'g'), ` ${replacement} `);
        }
      }
    }
    
    if (altQueryAllReplaced !== query) {
      altQueriesMapping[query].push(altQueryAllReplaced);
    }
    
    // Check for Cisco 'CM' and 'SME' abbreviations
    if (query.includes('cisco') && 
        (query.startsWith('cm ') || query.endsWith(' cm') || query.includes(' cm '))) {
      let altQuery = query.replace(/cm/g, 'communications manager');
      if (query.includes('sm')) {
        altQuery = altQuery.replace(/sm/g, 'session management');
      }
      altQueriesMapping[query].push(altQuery);
    }
    
    // Fix popular queries
    for (const [product, helperQuery] of Object.entries(POPULAR_QUERY_CORRECTIONS)) {
      if (query.includes(product) && !helperQuery.split(' ').some(word => query.includes(word))) {
        altQueriesMapping[query].push(`${helperQuery} ${query}`);
      }
    }
    
    // Check for different variants of js library names
    const queryWords = query.split(' ');
    if (query.includes('js ') || query.includes(' js') || query.endsWith('js')) {
      const altQueries: string[] = [];
      
      for (let i = 0; i < queryWords.length; i++) {
        let word = queryWords[i].trim();
        let newQueryWords1: string[] = [];
        let newQueryWords2: string[] = [];
        
        if (word === 'js' && i > 0) {
          newQueryWords1 = [...queryWords.slice(0, i - 1), queryWords[i - 1] + 'js'];
          newQueryWords2 = [...queryWords.slice(0, i - 1), queryWords[i - 1] + '.js'];
        } else if (word.endsWith('.js') || word.endsWith('js')) {
          if (i > 0) {
            newQueryWords1.push(...queryWords.slice(0, i));
            newQueryWords2.push(...queryWords.slice(0, i));
          }
          
          if (word.endsWith('.js')) {
            newQueryWords1.push(word.slice(0, -3), 'js');
            newQueryWords2.push(word.slice(0, -3) + 'js');
          } else {
            newQueryWords1.push(word.slice(0, -2), 'js');
            newQueryWords2.push(word.slice(0, -2) + '.js');
          }
        }
        
        if (newQueryWords1.length > 0) {
          if (i < queryWords.length - 1) {
            newQueryWords1.push(...queryWords.slice(i + 1));
            newQueryWords2.push(...queryWords.slice(i + 1));
          }
          altQueries.push(newQueryWords1.join(' '));
          altQueries.push(newQueryWords2.join(' '));
        }
      }
      
      if (altQueries.length > 0) {
        altQueriesMapping[query].push(...altQueries);
      }
    }
    
    // Check for version containing commit-ID, date, etc.
    const versionParts = getPossibleVersionsInQuery(query);
    if (versionParts.length > 1) {
      const queryNoVersion = query.replace(versionParts[0], '');
      altQueriesMapping[query].push(queryNoVersion + versionParts.slice(1).join(' '));
    }
    
    // Split version parts with different character groups
    let potAltQuery = '';
    let curCharClass = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let didSplit = false;
    let seenFirstBreak = false;
    let splits = 0;
    const maxsplit = query.split(' ').length + ALT_QUERY_MAXSPLIT;
    
    for (const char of query) {
      if ([' ', '.', '-', '+'].includes(char)) {
        seenFirstBreak = true;
        potAltQuery += char;
        didSplit = false;
        continue;
      }
      
      if (seenFirstBreak && splits < maxsplit && !curCharClass.includes(char) && !didSplit) {
        potAltQuery += ' ';
        didSplit = true;
        splits++;
        
        if (/[a-zA-Z]/.test(char)) {
          curCharClass = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        } else if (/[0-9]/.test(char)) {
          curCharClass = '0123456789';
        } else {
          curCharClass = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~';
        }
      }
      potAltQuery += char;
    }
    
    const potAltQueryParts = potAltQuery.split(' ').map(part => {
      if (part.length > 0 && ['.', '-', '+'].includes(part[part.length - 1])) {
        return part.slice(0, -1);
      }
      return part;
    });
    potAltQuery = potAltQueryParts.join(' ');
    
    if (potAltQuery !== query.trim()) {
      altQueriesMapping[query].push(potAltQuery);
      for (const word of query.split(' ')) {
        if (!potAltQuery.includes(word)) {
          potAltQuery += ' ' + word;
        }
      }
      altQueriesMapping[query].push(potAltQuery);
    }
    
    // Add alt query for likely subversion split from main version
    if (queryWords.length > 2 && queryWords[queryWords.length - 1].length < 7) {
      altQueriesMapping[query].push(query + ' ' + queryWords[queryWords.length - 2] + queryWords[queryWords.length - 1]);
      altQueriesMapping[query].push(
        queryWords.slice(0, -2).join(' ') + ' ' + queryWords[queryWords.length - 2] + queryWords[queryWords.length - 1]
      );
    }
    
    // Zero extend versions
    const versionMatch = query.match(VERSION_MATCH_ZE_RE);
    if (versionMatch) {
      altQueriesMapping[query].push(query.replace(versionMatch[0], versionMatch[0] + '.0'));
      altQueriesMapping[query].push(query.replace(versionMatch[0], versionMatch[0] + '.0.0'));
    }
  }
  
  return altQueriesMapping;
}

/**
 * Parse entry IDs string (e.g., "1,2,3" or "1-5,10")
 */
function parseEntryIds(idsStr: string): number[] {
  const ids: number[] = [];
  const parts = idsStr.split(',');
  
  for (const part of parts) {
    const trimmed = part.trim();
    if (trimmed.includes('-')) {
      const [start, end] = trimmed.split('-').map(s => parseInt(s, 10));
      if (!isNaN(start) && !isNaN(end)) {
        for (let i = start; i <= end; i++) {
          ids.push(i);
        }
      }
    } else {
      const id = parseInt(trimmed, 10);
      if (!isNaN(id)) {
        ids.push(id);
      }
    }
  }
  
  return ids;
}

/**
 * Core CPE search implementation
 */
function _searchCPEs(
  queriesRaw: string[],
  dbCursor: Database,
  count: number,
  threshold: number,
  config: CPESearchConfig
): Record<string, Array<[string, number]>> {
  
  // Create term frequencies for all queries
  const queries = queriesRaw.map(q => q.toLowerCase());
  
  // Add alternative queries
  const altQueriesMapping = getAlternativeQueries(queries);
  for (const altQueries of Object.values(altQueriesMapping)) {
    queries.push(...altQueries);
  }
  
  const queryInfos: Record<string, QueryInfo> = {};
  const mostSimilar: Record<string, Record<string, [string, number]>> = {};
  let allQueryWords = new Set<string>();
  const includedWordSets: Record<string, string[]> = {};
  
  for (const query of queries) {
    const wordsQuery = query.match(TEXT_TO_VECTOR_RE) || [];
    
    // Check if this word set was already included
    const wordsQueryStr = wordsQuery.join(',');
    if (Object.values(includedWordSets).some(ws => ws.join(',') === wordsQueryStr)) {
      continue;
    }
    includedWordSets[query] = wordsQuery;
    
    const wordWeightsQuery: Record<string, number> = {};
    for (let i = 0; i < wordsQuery.length; i++) {
      const word = wordsQuery[i];
      if (!(word in wordWeightsQuery)) {
        wordWeightsQuery[word] = Math.exp(QUERY_TERM_WEIGHT_EXP_FACTOR * i);
      }
    }
    
    // Compute query's TF vector
    const queryTf: Record<string, number> = {};
    for (const word of wordsQuery) {
      queryTf[word] = (queryTf[word] || 0) + 1;
    }
    
    const queryTfLen = Object.keys(queryTf).length;
    for (const [term, tf] of Object.entries(queryTf)) {
      queryTf[term] = wordWeightsQuery[term] * (tf / queryTfLen);
    }
    
    allQueryWords = new Set([...allQueryWords, ...Object.keys(queryTf)]);
    
    const queryAbs = Math.sqrt(Object.values(queryTf).reduce((sum, cnt) => sum + cnt ** 2, 0));
    queryInfos[query] = { tf: queryTf, abs: queryAbs };
    mostSimilar[query] = {};
  }
  
  const queriesFinal = Object.keys(includedWordSets);
  
  // Get relevant CPE entry IDs based on query terms
  const allCpeEntryIds: number[] = [];
  for (const word of allQueryWords) {
    try {
      const stmt = dbCursor.query('SELECT entry_ids FROM terms_to_entries WHERE term = ?');
      const result = stmt.get(word) as any;
      
      if (!result || !result.entry_ids) continue;
      
      const cpeEntryIds = result.entry_ids.split(',');
      allCpeEntryIds.push(parseInt(cpeEntryIds[0], 10));
      
      for (const eid of cpeEntryIds.slice(1)) {
        if (eid.includes('-')) {
          const [start, end] = eid.split('-').map((s: string) => parseInt(s, 10));
          for (let i = start; i <= end; i++) {
            allCpeEntryIds.push(i);
          }
        } else {
          allCpeEntryIds.push(parseInt(eid, 10));
        }
      }
    } catch (error) {
      // Term not found, continue
    }
  }
  
  // Fetch CPE entries in batches
  const allCpeInfos: Array<[string, string, number]> = [];
  let remaining = allCpeEntryIds.length;
  const maxResultsPerQuery = 1000;
  
  while (remaining > 0) {
    const countParamsInStr = Math.min(remaining, maxResultsPerQuery);
    const batch = allCpeEntryIds.slice(remaining - countParamsInStr, remaining);
    const placeholders = batch.map(() => '?').join(',');
    
    const stmt = dbCursor.query(
      `SELECT cpe, term_frequencies, abs_term_frequency 
       FROM cpe_entries 
       WHERE entry_id IN (${placeholders})`
    );
    const cpeInfos = stmt.all(...batch) as any[];
    
    for (const info of cpeInfos) {
      allCpeInfos.push([info.cpe, info.term_frequencies, info.abs_term_frequency]);
    }
    
    remaining -= maxResultsPerQuery;
  }
  
  // Calculate similarity scores
  const processedCpes = new Set<string>();
  
  for (const cpeInfo of allCpeInfos) {
    const [cpe, cpeTfStr, cpeAbsVal] = cpeInfo;
    
    if (processedCpes.has(cpe)) continue;
    processedCpes.add(cpe);
    
    const cpeTf = JSON.parse(cpeTfStr);
    const cpeAbs = parseFloat(cpeAbsVal.toString());
    
    for (const query of queriesFinal) {
      const { tf: queryTf, abs: queryAbs } = queryInfos[query];
      const intersectingWords = Object.keys(cpeTf).filter(w => w in queryTf);
      const innerProduct = intersectingWords.reduce((sum, w) => sum + cpeTf[w] * queryTf[w], 0);
      
      const normalizationFactor = cpeAbs * queryAbs;
      if (normalizationFactor === 0) continue;
      
      const simScore = innerProduct / normalizationFactor;
      
      if (threshold > 0 && simScore < threshold) continue;
      
      const cpeBase = cpe.split(':').slice(0, 5).join(':') + ':';
      const nonWildcards = cpe.split(':').filter(f => !['*', '-', ''].includes(f)).length;
      const cpeClass = `${cpeBase}-${10 - (cpe.split(':').length - nonWildcards)}`;
      
      if (!mostSimilar[query][cpeClass] || simScore > mostSimilar[query][cpeClass][1]) {
        mostSimilar[query][cpeClass] = [cpe, simScore];
      }
    }
  }
  
  // Unify results per query
  for (const query of queriesFinal) {
    if (mostSimilar[query] && Object.keys(mostSimilar[query]).length > 0) {
      const unifiedMostSimilar = new Set(Object.values(mostSimilar[query]));
      mostSimilar[query] = Object.fromEntries(
        Array.from(unifiedMostSimilar)
          .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
          .map((entry, idx) => [idx.toString(), entry])
      );
    }
  }
  
  // Limit results per query
  if (count !== -1) {
    for (const query of queriesFinal) {
      if (mostSimilar[query]) {
        const entries = Object.values(mostSimilar[query]).slice(0, count);
        mostSimilar[query] = Object.fromEntries(entries.map((e, i) => [i.toString(), e]));
      }
    }
  }
  
  // Create intermediate results
  const intermediateResults: Record<string, Array<[string, number]>> = {};
  for (const query of queriesFinal) {
    const results = Object.values(mostSimilar[query] || {});
    if (results.length === 0 || (results.length === 1 && results[0][1] === -1)) {
      continue;
    }
    intermediateResults[query] = results.filter(r => r[1] !== -1);
  }
  
  // Create final results for original queries
  const results: Record<string, Array<[string, number]>> = {};
  
  for (const queryRaw of queriesRaw) {
    const query = queryRaw.toLowerCase();
    
    if (!(query in intermediateResults) && 
        (!(query in altQueriesMapping) || altQueriesMapping[query].length === 0)) {
      continue;
    }
    
    if (!(query in altQueriesMapping) || altQueriesMapping[query].length === 0) {
      results[queryRaw] = intermediateResults[query];
    } else {
      const unifiedSet = new Set(intermediateResults[query] || []);
      
      for (const altQuery of altQueriesMapping[query]) {
        if (altQuery !== query && intermediateResults[altQuery]) {
          for (const entry of intermediateResults[altQuery]) {
            unifiedSet.add(entry);
          }
        }
      }
      
      results[queryRaw] = Array.from(unifiedSet).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    }
  }
  
  // Final count limitation
  if (count !== -1) {
    for (const query of queriesRaw) {
      if (results[query]) {
        results[query] = results[query].slice(0, count);
      } else {
        results[query] = [];
      }
    }
  }
  
  return results;
}

/**
 * Check if two CPEs are equal
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
 * Create CPEs from base CPE and query
 */
function createCpesFromBaseCpeAndQuery(cpe: string, query: string): string[] {
  const newCpes: string[] = [];
  const versionParts = getPossibleVersionsInQuery(query);
  
  // Create CPEs where version parts are put into subsequent CPE fields
  if (versionParts.length > 2) {
    for (let i = 1; i < versionParts.length; i++) {
      const cpeParts = cpe.split(':');
      const newParts = [...cpeParts.slice(0, 5), ...versionParts.slice(1, i + 1), ...cpeParts.slice(5 + i)];
      newCpes.push(newParts.join(':'));
    }
  }
  
  // Check for complex version without distinct separator
  if (versionParts.length === 1) {
    const complexVersionMatch = versionParts[0].match(VERSION_SPLIT_DIFF_CHARSETS_RE);
    if (complexVersionMatch) {
      const splitIdx = complexVersionMatch.index || 0;
      let verPart1 = versionParts[0].substring(0, splitIdx);
      let verPart2 = versionParts[0].substring(splitIdx);
      
      while (verPart2.length > 0 && !/[a-zA-Z0-9]/.test(verPart2[0])) {
        verPart2 = verPart2.substring(1);
      }
      
      if (verPart2) {
        const cpeParts = cpe.split(':');
        cpeParts[5] = verPart1;
        cpeParts[6] = verPart2;
        newCpes.push(cpeParts.join(':'));
      }
    }
  }
  
  // Check if version part already in CPE
  let versionPartInCpe = false;
  for (let i = 0; i < versionParts.length - 2; i++) {
    const version = versionParts[i + 2];
    const cpeParts = cpe.split(':');
    if (cpeParts.slice(6 + i).includes(version)) {
      versionPartInCpe = true;
      break;
    }
  }
  
  // Create CPE with full version string
  if (versionParts.length > 0 && !versionPartInCpe) {
    const cpeParts = cpe.split(':');
    cpeParts[5] = versionParts[0].replace(/ /g, '_');
    newCpes.push(cpeParts.join(':'));
  }
  
  return newCpes;
}

/**
 * Check if query is versionless
 */
function isVersionlessQuery(query: string): boolean {
  const versionStrMatch = query.match(VERSION_MATCH_CPE_CREATION_RE);
  return !versionStrMatch;
}

/**
 * Create base CPE if query is versionless
 */
function createBaseCpeIfVersionlessQuery(cpe: string, query: string): string | null {
  if (isVersionlessQuery(query)) {
    const cpeParts = cpe.split(':');
    const baseCpe = [...cpeParts.slice(0, 5), ...Array(8).fill('*')].join(':');
    return baseCpe;
  }
  return null;
}

/**
 * Check if CPE matches query
 */
function cpeMatchesQuery(cpe: string, query: string): boolean {
  const checkStr = cpe.substring(8);
  let badMatch = false;
  
  // Ensure CPE has a number if query has a number
  if (/\d/.test(query) && !/\d/.test(checkStr)) {
    badMatch = true;
  }
  
  // Check if version in query is reflected in CPE
  const versionsInQuery = getPossibleVersionsInQuery(query);
  if (!badMatch) {
    let cpeHasMatchingVersion = false;
    
    for (const possibleVersion of versionsInQuery) {
      if (!possibleVersion.includes('.')) continue;
      
      let idxPosVer = 0;
      let idxCheckStr = 0;
      
      while (idxPosVer < possibleVersion.length && idxCheckStr < checkStr.length) {
        while (idxPosVer < possibleVersion.length && !/\d/.test(possibleVersion[idxPosVer])) {
          idxPosVer++;
        }
        if (idxPosVer < possibleVersion.length && possibleVersion[idxPosVer] === checkStr[idxCheckStr]) {
          idxPosVer++;
        }
        idxCheckStr++;
      }
      
      if (idxPosVer === possibleVersion.length) {
        cpeHasMatchingVersion = true;
        break;
      }
    }
    
    if (versionsInQuery.length > 0 && !cpeHasMatchingVersion) {
      badMatch = true;
    }
  }
  
  // Check that at least one query term (not version) is in CPE
  if (!badMatch) {
    const nonVersionTerms = query.split(' ')
      .filter(term => !versionsInQuery.includes(term))
      .map(term => term.toLowerCase());
    
    if (!nonVersionTerms.some(term => cpe.includes(term))) {
      badMatch = true;
    }
  }
  
  return !badMatch;
}

/**
 * Main search CPEs function - exact port of Python version
 */
export async function search_cpes(
  query: string,
  db_cursor: Database,
  count: number | null = null,
  threshold: number | null = null,
  config: CPESearchConfig = {}
): Promise<CPESearchResult> {
  
  if (!query) {
    return { cpes: [], pot_cpes: [] };
  }
  
  const finalCount = count !== null ? count : (config.CPE_SEARCH_COUNT || 10);
  const finalThreshold = threshold !== null ? threshold : (config.CPE_SEARCH_THRESHOLD || 0.68);
  
  const trimmedQuery = query.trim();
  let cpes: Array<[string, number]> = [];
  let potCpes: Array<[string, number]> = [];
  
  if (!MATCH_CPE_23_RE.test(trimmedQuery)) {
    const searchResults = _searchCPEs(
      [trimmedQuery],
      db_cursor,
      finalCount,
      CPE_SEARCH_THRESHOLD_ALT,
      config
    );
    
    cpes = searchResults[trimmedQuery] || [];
    
    if (cpes.length === 0) {
      return { cpes: [], pot_cpes: [] };
    }
    
    // Clean query for CPE creation
    let cpeCreationQuery = trimmedQuery.replace(CPE_CREATION_DEL_SYMBOLS_RE, ' ');
    cpeCreationQuery = cpeCreationQuery.replace(/  /g, ' ');
    
    // Create related CPEs with version
    for (const [cpe, sim] of cpes) {
      const newCpes = createCpesFromBaseCpeAndQuery(cpe, cpeCreationQuery);
      
      for (const newCpe of newCpes) {
        if (cpes.some(([existingCpe]) => isCpeEqual(newCpe, existingCpe))) {
          continue;
        }
        
        if (!potCpes.some(([other]) => isCpeEqual(newCpe, other))) {
          potCpes.push([newCpe, -1 * sim]);
        }
      }
      
      if (!potCpes.some(([other]) => isCpeEqual(cpe, other))) {
        potCpes.push([cpe, sim]);
      }
    }
    
    // Create versionless CPEs if query is versionless
    const versionlessCpeInserts: Array<[[string, number], number]> = [];
    let newIdx = 0;
    
    for (const [cpe, sim] of potCpes) {
      const baseCpe = createBaseCpeIfVersionlessQuery(cpe, cpeCreationQuery);
      if (baseCpe) {
        if (!potCpes.some(([other]) => isCpeEqual(baseCpe, other)) &&
            !versionlessCpeInserts.some(([[other]]) => isCpeEqual(baseCpe, other))) {
          versionlessCpeInserts.push([[baseCpe, -1 * sim], newIdx]);
        }
      }
      newIdx++;
    }
    
    for (const [newCpe, idx] of versionlessCpeInserts) {
      potCpes.splice(idx, 0, newCpe);
    }
    
    // Filter bad CPE matches
    const prevCpeCount = cpes.length;
    cpes = cpes.filter(([cpe]) => cpeMatchesQuery(cpe, cpeCreationQuery));
    
    // Break early on bad match
    if (prevCpeCount !== cpes.length) {
      if (cpes.length > 0 && cpes[0][1] > finalThreshold) {
        return { cpes, pot_cpes: potCpes };
      } else {
        const newPotCpes = potCpes.filter(([potCpe]) => {
          const words = potCpe.split(':').slice(3, 5);
          return words.some(word => trimmedQuery.toLowerCase().includes(word.toLowerCase()));
        });
        return { cpes: [], pot_cpes: newPotCpes };
      }
    }
    
    // Check for versionless query with versioned CPE
    const cpeVersion = cpes[0][0].split(':')[5] || '';
    if (cpeVersion && cpeVersion !== '*' && cpeVersion !== '-') {
      const baseCpe = createBaseCpeIfVersionlessQuery(cpes[0][0], trimmedQuery);
      if (baseCpe) {
        const potCpesVersionless = potCpes.filter(([potCpe]) => {
          const cpeVersionIter = potCpe.split(':')[5] || '';
          return ['', '*', '-'].includes(cpeVersionIter);
        });
        return { cpes: [], pot_cpes: potCpesVersionless };
      }
    }
    
    if (cpes.length > 0 && cpes[0][1] < finalThreshold) {
      cpes = [];
    }
  } else {
    potCpes = [];
  }
  
  return { cpes, pot_cpes: potCpes };
}
