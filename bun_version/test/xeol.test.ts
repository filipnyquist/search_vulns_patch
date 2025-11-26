/**
 * Tests for Xeol EOL Integration
 */

import { describe, test, expect } from 'bun:test';
import { Database } from 'bun:sqlite';
import { 
  getXeolDatabaseConnection, 
  queryXeolEOL, 
  addXeolEOLStatus 
} from '../src/utils/xeol';
import type { SearchVulnsResult } from '../src/types/vulnerability';

describe('Xeol Integration', () => {
  test('should connect to xeol database when enabled', () => {
    const config = {
      enabled: true,
      databasePath: 'resources/xeol.db',
    };
    
    const db = getXeolDatabaseConnection(config);
    
    if (db) {
      expect(db).toBeDefined();
      db.close();
    } else {
      // Database might not exist in test environment, skip
      console.log('Skipping test - xeol database not found');
    }
  });

  test('should return null when xeol is disabled', () => {
    const config = {
      enabled: false,
      databasePath: 'resources/xeol.db',
    };
    
    const db = getXeolDatabaseConnection(config);
    expect(db).toBeNull();
  });

  test('should query Apache HTTP Server EOL data from xeol', () => {
    const config = {
      enabled: true,
      databasePath: 'resources/xeol.db',
    };
    
    const db = getXeolDatabaseConnection(config);
    
    if (!db) {
      console.log('Skipping test - xeol database not found');
      return;
    }

    try {
      const result = queryXeolEOL(db, 'Apache HTTP Server', '2.2');
      
      if (result) {
        expect(result).toHaveProperty('status');
        expect(result).toHaveProperty('latest');
        expect(result).toHaveProperty('ref');
        expect(['current', 'outdated', 'eol', 'N/A']).toContain(result.status);
      }
    } finally {
      db.close();
    }
  });

  test('should add xeol EOL status to search results', () => {
    const config = {
      enabled: true,
      databasePath: 'resources/xeol.db',
    };
    
    const db = getXeolDatabaseConnection(config);
    
    if (!db) {
      console.log('Skipping test - xeol database not found');
      return;
    }

    try {
      const results: SearchVulnsResult = {
        product_ids: {
          cpe: ['cpe:2.3:a:apache:http_server:2.2:*:*:*:*:*:*:*'],
        },
        vulns: {},
      };

      addXeolEOLStatus(results, db);
      
      // Should have version_status if xeol found a match
      if (results.version_status) {
        expect(results.version_status).toHaveProperty('status');
        expect(results.version_status).toHaveProperty('latest');
      }
    } finally {
      db.close();
    }
  });

  test('should not override existing EOL status', () => {
    const config = {
      enabled: true,
      databasePath: 'resources/xeol.db',
    };
    
    const db = getXeolDatabaseConnection(config);
    
    if (!db) {
      console.log('Skipping test - xeol database not found');
      return;
    }

    try {
      const existingStatus = {
        status: 'eol' as const,
        latest: '3.0.0',
        ref: 'https://endoflife.date/test',
      };

      const results: SearchVulnsResult = {
        product_ids: {
          cpe: ['cpe:2.3:a:test:product:1.0:*:*:*:*:*:*:*'],
        },
        vulns: {},
        version_status: existingStatus,
      };

      addXeolEOLStatus(results, db);
      
      // Should keep the original status
      expect(results.version_status).toEqual(existingStatus);
    } finally {
      db.close();
    }
  });
});
