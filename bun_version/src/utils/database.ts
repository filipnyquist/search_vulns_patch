import { Database } from 'bun:sqlite';
import type { DatabaseConfig } from '../types/config';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Get a database connection based on configuration
 */
export function getDatabaseConnection(dbConfig: DatabaseConfig): Database {
  const dbType = dbConfig.TYPE || 'sqlite';

  if (dbType !== 'sqlite') {
    throw new Error(`Database type '${dbType}' is not supported. Only SQLite is supported.`);
  }

  if (!dbConfig.NAME) {
    throw new Error('Database NAME is required for SQLite');
  }

  let dbPath = dbConfig.NAME;

  // Make path absolute if it's relative
  if (!dbPath.startsWith('/') && !dbPath.startsWith('~')) {
    // Resolve relative to the project root (parent of src)
    dbPath = resolve(__dirname, '../../', dbPath);
  }

  try {
    const db = new Database(dbPath, { readonly: true });
    return db;
  } catch (error) {
    throw new Error(`Failed to open database at ${dbPath}: ${error}`);
  }
}

/**
 * Execute a SQL query and return results
 */
export function executeQuery(db: Database, query: string, params: any[] = []): any[] {
  try {
    const stmt = db.query(query);
    return stmt.all(...params);
  } catch (error) {
    console.error(`Failed to execute query: ${query}`, error);
    throw error;
  }
}

/**
 * Execute a SQL query and return a single result
 */
export function executeQueryOne(db: Database, query: string, params: any[] = []): any | null {
  try {
    const stmt = db.query(query);
    return stmt.get(...params) || null;
  } catch (error) {
    console.error(`Failed to execute query: ${query}`, error);
    throw error;
  }
}
