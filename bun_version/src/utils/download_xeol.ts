#!/usr/bin/env bun
/**
 * Utility script to download and setup xeol database
 */

import { downloadXeolDatabase } from './xeol';
import { resolve } from 'path';

const DEFAULT_TARGET_PATH = resolve(import.meta.dir, '../../resources/xeol.db');

async function main() {
  const args = process.argv.slice(2);
  const targetPath = args[0] || DEFAULT_TARGET_PATH;
  
  console.log('Xeol Database Downloader');
  console.log('========================\n');
  console.log(`Target path: ${targetPath}\n`);
  
  const success = await downloadXeolDatabase(targetPath);
  
  if (success) {
    console.log('\n✓ Xeol database downloaded and extracted successfully!');
    console.log('\nTo enable xeol in your config.json, set:');
    console.log('  "XEOL_DATABASE": {');
    console.log('    "ENABLED": true,');
    console.log(`    "DATABASE_PATH": "${targetPath}"`);
    console.log('  }');
    process.exit(0);
  } else {
    console.error('\n✗ Failed to download xeol database');
    process.exit(1);
  }
}

main();
