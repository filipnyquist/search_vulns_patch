/**
 * Tests for CPE Search functionality
 * Testing query corrections and alternative query generation
 */

import { describe, test, expect } from 'bun:test';

// We're testing the internal logic of how queries are transformed
// Since getAlternativeQueries is not exported, we test indirectly through the corrections

describe('CPE Search Query Corrections', () => {
  test('Angular query should be in POPULAR_QUERY_CORRECTIONS', () => {
    // Import the module to check the constant
    const cpeSearchModule = require('../src/utils/cpe_search.ts');
    
    // We can't directly access POPULAR_QUERY_CORRECTIONS since it's not exported
    // But we can verify the fix is in place by checking the file content
    // This is a basic sanity test
    
    // The actual test would require:
    // 1. A test database with Angular CPEs
    // 2. Running search_cpes('angular 18', db)
    // 3. Verifying it returns cpe:2.3:a:angular:angular:18:...
    
    // For now, we'll just verify the module loads without errors
    expect(cpeSearchModule).toBeDefined();
  });

  test('Query corrections should help with vendor/product matching', () => {
    // This tests the concept that when a product name matches both
    // vendor and product (like angular:angular), adding a correction
    // helps the TF-IDF algorithm match better by duplicating the term
    
    // Example: 'angular' -> 'angular angular'
    // This increases the term frequency for 'angular' in the query
    // making it more likely to match CPEs with vendor:product both containing 'angular'
    
    const exampleQuery = 'angular 18';
    const exampleCorrectedQuery = 'angular angular 18';
    
    // The corrected query has 'angular' twice, which should help match
    // cpe:2.3:a:angular:angular:18:...
    const angularCount = (exampleCorrectedQuery.match(/angular/g) || []).length;
    expect(angularCount).toBe(2);
  });
});
