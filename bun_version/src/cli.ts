#!/usr/bin/env bun
import { parseArgs } from 'util';
import { searchVulns, serializeVulnsInResult, getVersion } from './core.ts';
import { loadConfig } from './utils/config.ts';
import type { Vulnerability } from './types/vulnerability.ts';
import type { SearchVulnsResult } from './types/vulnerability.ts';

// ANSI color codes
const SANE = '\u001b[0m';
const GREEN = '\u001b[32m';
const BRIGHT_GREEN = '\u001b[32;1m';
const RED = '\u001b[31m';
const YELLOW = '\u001b[33m';
const BRIGHT_BLUE = '\u001b[34;1m';
const MAGENTA = '\u001b[35m';

/**
 * Print colored text
 */
function printit(text: string = '', color: string = SANE, end: string = '\n'): void {
  if (color !== SANE) {
    process.stdout.write(color);
  }
  process.stdout.write(text + end);
  if (color !== SANE) {
    process.stdout.write(SANE);
  }
}

/**
 * Format and print vulnerabilities
 */
function printVulns(vulns: Record<string, Vulnerability>, toString: boolean = false): string {
  let outString = '';

  // Sort by CVSS score (highest first)
  const vulnIdsSorted = Object.keys(vulns).sort((a, b) => {
    const cvssA = parseFloat(vulns[a].cvss) || 0;
    const cvssB = parseFloat(vulns[b].cvss) || 0;
    return cvssB - cvssA;
  });

  for (const vulnId of vulnIdsSorted) {
    const vuln = vulns[vulnId];
    const description = vuln.description.trim().replace(/(\r\n)+/g, '\r\n').replace(/\n+/g, '\n');

    let printStr = '';
    if (!toString) {
      printStr = GREEN + vuln.id + SANE;
      printStr += ' (' + MAGENTA + 'CVSSv' + vuln.cvssVer + '/' + vuln.cvss + SANE + ')';
      if (vuln.cisaKnownExploited) {
        printStr += ' (' + RED + 'Actively exploited' + SANE + ')';
      }
    } else {
      printStr = vuln.id;
      printStr += ' (CVSSv' + vuln.cvssVer + '/' + vuln.cvss + ')';
      if (vuln.cisaKnownExploited) {
        printStr += ' (Actively exploited)';
      }
    }
    printStr += ': ' + description + '\n';

    if (vuln.exploits.size > 0) {
      const exploitList = Array.from(vuln.exploits);
      if (!toString) {
        printStr += YELLOW + 'Exploits:  ' + SANE + exploitList[0] + '\n';
      } else {
        printStr += 'Exploits:  ' + exploitList[0] + '\n';
      }

      if (exploitList.length > 1) {
        for (let i = 1; i < exploitList.length; i++) {
          printStr += ' '.repeat('Exploits:  '.length) + exploitList[i] + '\n';
        }
      }
    }

    printStr += 'Reference: ' + vuln.aliases[vuln.id];
    if (vuln.published) {
      printStr += ', ' + vuln.published.split(' ')[0];
    }

    if (!toString) {
      printit(printStr);
    } else {
      outString += printStr + '\n';
    }
  }

  return outString;
}

/**
 * Print usage information
 */
function printHelp(): void {
  console.log(`
usage: bun run cli.ts [options]

Search for known vulnerabilities in software -- Bun.js/TypeScript implementation

options:
  -h, --help                              Show this help message and exit
  -q, --query <QUERY>                     A query, either software title like 'Apache 2.4.39' or a product ID string (e.g. CPE 2.3)
  -c, --config <FILE>                     A config file to use (default: config.json)
  -V, --version                           Print the version of search_vulns
  -f, --format <txt|json>                 Output format, either 'txt' or 'json' (default: 'txt')
  -o, --output <FILE>                     File to write found vulnerabilities to
  --ignore-general-product-vulns          Ignore vulnerabilities that only affect a general product
  --include-single-version-vulns          Include vulnerabilities that only affect one specific version
  --include-patched                       Include vulnerabilities reported as (back)patched

examples:
  bun run cli.ts -q 'Sudo 1.8.2'
  bun run cli.ts -q 'CVE-2024-27286, GHSA-hfjr-m75m-wmh7'
  bun run cli.ts -q 'Apache 2.4.39' -f json
`);
}

/**
 * Main CLI function
 */
async function main() {
  const args = process.argv.slice(2);

  // Parse arguments manually for better control
  const options: {
    queries: string[];
    config?: string;
    version: boolean;
    format: 'txt' | 'json';
    output?: string;
    ignoreGeneralProductVulns: boolean;
    includeSingleVersionVulns: boolean;
    includePatched: boolean;
    help: boolean;
  } = {
    queries: [],
    version: false,
    format: 'txt',
    ignoreGeneralProductVulns: false,
    includeSingleVersionVulns: false,
    includePatched: false,
    help: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    switch (arg) {
      case '-h':
      case '--help':
        options.help = true;
        break;
      case '-q':
      case '--query':
        if (i + 1 < args.length) {
          options.queries.push(args[++i]);
        }
        break;
      case '-c':
      case '--config':
        if (i + 1 < args.length) {
          options.config = args[++i];
        }
        break;
      case '-V':
      case '--version':
        options.version = true;
        break;
      case '-f':
      case '--format':
        if (i + 1 < args.length) {
          const fmt = args[++i];
          if (fmt === 'txt' || fmt === 'json') {
            options.format = fmt;
          }
        }
        break;
      case '-o':
      case '--output':
        if (i + 1 < args.length) {
          options.output = args[++i];
        }
        break;
      case '--ignore-general-product-vulns':
        options.ignoreGeneralProductVulns = true;
        break;
      case '--include-single-version-vulns':
        options.includeSingleVersionVulns = true;
        break;
      case '--include-patched':
        options.includePatched = true;
        break;
    }
  }

  // Show help if requested or no arguments
  if (options.help || (args.length === 0 && !options.version)) {
    printHelp();
    process.exit(0);
  }

  // Show version
  if (options.version) {
    console.log(getVersion());
    if (options.queries.length === 0) {
      process.exit(0);
    }
  }

  // Load configuration
  const config = await loadConfig(options.config);

  // Process queries
  const allVulns: Record<string, SearchVulnsResult | string> = {};
  let outString = '';

  for (const query of options.queries) {
    const queryTrimmed = query.trim();

    if (options.format === 'txt') {
      if (!options.output) {
        printit(`[+] ${queryTrimmed} (`, BRIGHT_BLUE, '');
      } else {
        outString += `[+] ${queryTrimmed} (`;
      }
    }

    try {
      const svResult = await searchVulns(
        queryTrimmed,
        null,
        null,
        null,
        false,
        options.ignoreGeneralProductVulns,
        options.includeSingleVersionVulns,
        options.includePatched,
        config
      );

      const allProductIds: string[] = [];
      for (const pids of Object.values(svResult.product_ids)) {
        allProductIds.push(...pids);
      }

      const isGoodResult = svResult.vulns && Object.keys(svResult.vulns).length > 0;

      if (!isGoodResult && allProductIds.length === 0) {
        if (options.format === 'txt') {
          if (!options.output) {
            printit(')', BRIGHT_BLUE);
            printit('Warning: Could not find matching software for query', RED);
            printit();
          } else {
            outString += ')\nWarning: Could not find matching software for query\n\n';
          }
        } else {
          allVulns[queryTrimmed] = 'Warning: Could not find matching software for query';
        }
        continue;
      }

      if (options.format === 'txt') {
        const productIdsStr = allProductIds.join('/');
        if (!options.output) {
          printit(productIdsStr + ')', BRIGHT_BLUE);
        } else {
          outString += productIdsStr + ')\n';
        }
      }

      // Sort vulnerabilities by CVSS
      if (svResult.vulns) {
        const vulnIdsSorted = Object.keys(svResult.vulns).sort((a, b) => {
          const cvssA = parseFloat(svResult.vulns[a].cvss) || 0;
          const cvssB = parseFloat(svResult.vulns[b].cvss) || 0;
          return cvssB - cvssA;
        });
        const sortedVulns: Record<string, Vulnerability> = {};
        for (const vulnId of vulnIdsSorted) {
          sortedVulns[vulnId] = svResult.vulns[vulnId];
        }
        svResult.vulns = sortedVulns;
      }

      // Output results
      if (options.format === 'txt') {
        if (!options.output) {
          printVulns(svResult.vulns);
        } else {
          outString += printVulns(svResult.vulns, true);
        }
      } else {
        serializeVulnsInResult(svResult);
      }

      allVulns[queryTrimmed] = svResult;
    } catch (error) {
      console.error(`Error processing query '${queryTrimmed}':`, error);
    }
  }

  // Write output to file or stdout
  if (options.output) {
    if (options.format === 'json') {
      await Bun.write(options.output, JSON.stringify(allVulns, null, 2));
    } else {
      await Bun.write(options.output, outString);
    }
  } else if (options.format === 'json') {
    console.log(JSON.stringify(allVulns, null, 2));
  }
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
