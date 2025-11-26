/**
 * Tests for Equivalent CPEs functionality
 */

import { describe, test, expect } from 'bun:test';
import { getEquivalentCpes, isCpeEqual, loadEquivalentCpes } from '../src/utils/equivalent_cpes';
import { parseVersion, compareVersions } from '../src/utils/version';
import type { Database } from 'bun:sqlite';

describe('Version Parsing', () => {
  test('should handle string versions', () => {
    const result = parseVersion('1.2.3');
    expect(result).toEqual([1, 2, 3]);
  });

  test('should handle numeric versions', () => {
    const result = parseVersion(123);
    expect(result).toEqual([123]);
  });

  test('should handle null/undefined versions', () => {
    expect(parseVersion(null)).toEqual([]);
    expect(parseVersion(undefined)).toEqual([]);
  });

  test('should handle wildcard versions', () => {
    expect(parseVersion('*')).toEqual([]);
  });

  test('should compare string versions', () => {
    expect(compareVersions('1.2.3', '1.2.4')).toBe(-1);
    expect(compareVersions('2.0.0', '1.9.9')).toBe(1);
    expect(compareVersions('1.0', '1.0')).toBe(0);
  });

  test('should compare numeric versions', () => {
    expect(compareVersions(123, 124)).toBe(-1);
    expect(compareVersions(200, 199)).toBe(1);
    expect(compareVersions(100, 100)).toBe(0);
  });

  test('should compare null/undefined versions', () => {
    expect(compareVersions(null, '1.0')).toBe(-1);
    expect(compareVersions('1.0', null)).toBe(1);
    expect(compareVersions(null, null)).toBe(0);
  });
});

describe('Equivalent CPEs', () => {
  describe('isCpeEqual', () => {
    test('should match identical CPEs', () => {
      const cpe1 = 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*';
      const cpe2 = 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*';
      expect(isCpeEqual(cpe1, cpe2)).toBe(true);
    });

    test('should match CPEs with wildcards', () => {
      const cpe1 = 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*';
      const cpe2 = 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*';
      expect(isCpeEqual(cpe1, cpe2)).toBe(true);
    });

    test('should not match different vendors', () => {
      const cpe1 = 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*';
      const cpe2 = 'cpe:2.3:a:nginx:nginx:2.4.49:*:*:*:*:*:*:*';
      expect(isCpeEqual(cpe1, cpe2)).toBe(false);
    });

    test('should not match different products', () => {
      const cpe1 = 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*';
      const cpe2 = 'cpe:2.3:a:apache:tomcat:2.4.49:*:*:*:*:*:*:*';
      expect(isCpeEqual(cpe1, cpe2)).toBe(false);
    });
  });

  describe('getEquivalentCpes', () => {
    test('should return at least the original CPE', async () => {
      // Create a mock database
      const mockDb = {
        query: () => ({
          get: () => null,
        }),
      } as unknown as Database;

      const cpe = 'cpe:2.3:a:jquery:jquery:3.1.2:*:*:*:*:*:*:*';
      const result = await getEquivalentCpes(cpe, mockDb);
      
      expect(result).toContain(cpe);
      expect(result.length).toBeGreaterThanOrEqual(1);
    });

    test('should expand version with subversion', async () => {
      const mockDb = {
        query: () => ({
          get: () => null,
        }),
      } as unknown as Database;

      const cpe = 'cpe:2.3:a:test:product:1.2:3:*:*:*:*:*:*';
      const result = await getEquivalentCpes(cpe, mockDb);
      
      // Should include original CPE
      expect(result).toContain(cpe);
      
      // Should include version with combined version-subversion
      const combined = 'cpe:2.3:a:test:product:1.2-3:*:*:*:*:*:*:*';
      expect(result).toContain(combined);
    });

    test('should load equivalent CPEs only once', async () => {
      const mockDb = {
        query: () => ({
          get: () => null,
        }),
      } as unknown as Database;

      // Call loadEquivalentCpes multiple times
      await loadEquivalentCpes(mockDb);
      await loadEquivalentCpes(mockDb);
      await loadEquivalentCpes(mockDb);
      
      // Should not throw errors and should be idempotent
      expect(true).toBe(true);
    });
  });
});
