import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { Config } from '../types/config';
import { DEFAULT_CONFIG } from '../types/config';

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Load configuration from a file
 */
export async function loadConfig(configFile?: string): Promise<Config> {
  const configPath = configFile || resolve(__dirname, '../../config.json');

  try {
    const file = Bun.file(configPath);
    const configText = await file.text();
    const config = JSON.parse(configText) as Config;

    // Process database paths
    for (const dbKey of ['VULN_DATABASE', 'PRODUCT_DATABASE'] as const) {
      const db = config[dbKey];

      // Copy connection values from shared connection entry if needed
      let copyConnectionValues = true;
      for (const connInfo of ['TYPE', 'HOST', 'USER', 'PASSWORD', 'PORT'] as const) {
        if (config.DATABASE_CONNECTION[connInfo] && db[connInfo]) {
          copyConnectionValues = false;
          break;
        }
      }

      if (copyConnectionValues) {
        for (const connInfo of ['TYPE', 'HOST', 'USER', 'PASSWORD', 'PORT'] as const) {
          if (config.DATABASE_CONNECTION[connInfo]) {
            (db as any)[connInfo] = config.DATABASE_CONNECTION[connInfo];
          }
        }
      }

      // Make SQLite paths absolute
      const dbType = db.TYPE || config.DATABASE_CONNECTION.TYPE || 'sqlite';
      if (dbType === 'sqlite' && db.NAME) {
        let dbPath = db.NAME;

        if (!dbPath.startsWith('/')) {
          // Check if it's a home-relative path
          if (dbPath.startsWith('~')) {
            dbPath = dbPath.replace(/^~/, process.env.HOME || '~');
          } else {
            // Make relative to config file directory
            const configDir = dirname(configPath);
            dbPath = resolve(configDir, dbPath);
          }
          db.NAME = dbPath;
        }
      }
    }

    return config;
  } catch (error) {
    console.error(`Failed to load config from ${configPath}:`, error);
    // Return default config if file doesn't exist
    return { ...DEFAULT_CONFIG };
  }
}

/**
 * Get the default config file path
 */
export function getDefaultConfigPath(): string {
  return resolve(__dirname, '../../config.json');
}
