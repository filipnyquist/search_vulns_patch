import { describe, test, expect } from 'bun:test';
import { Vulnerability, MatchReason } from '../src/types/vulnerability.ts';
import { mergeModuleVulns } from '../src/core.ts';

describe('Vulnerability', () => {
  test('should create a vulnerability with required fields', () => {
    const vuln = new Vulnerability({
      id: 'CVE-2024-1234',
      matchReason: MatchReason.VULN_ID,
      matchSources: ['test'],
      description: 'Test vulnerability',
    });

    expect(vuln.id).toBe('CVE-2024-1234');
    expect(vuln.matchReason).toBe(MatchReason.VULN_ID);
    expect(vuln.matchSources).toEqual(['test']);
    expect(vuln.description).toBe('Test vulnerability');
  });

  test('should merge vulnerabilities correctly', () => {
    const vuln1 = new Vulnerability({
      id: 'CVE-2024-1234',
      matchReason: MatchReason.VULN_ID,
      matchSources: ['source1'],
      description: 'First description',
      cvss: '7.5',
    });

    const vuln2 = new Vulnerability({
      id: 'CVE-2024-1234',
      matchReason: MatchReason.PRODUCT_MATCH,
      matchSources: ['source2'],
      description: 'Better description',
      cvss: '8.5',
    });

    vuln1.mergeWithVulnerability(vuln2);

    expect(vuln1.id).toBe('CVE-2024-1234');
    expect(vuln1.matchReason).toBe(MatchReason.PRODUCT_MATCH);
    expect(vuln1.matchSources).toContain('source1');
    expect(vuln1.matchSources).toContain('source2');
    expect(vuln1.cvss).toBe('8.5');
  });

  test('should serialize to dict correctly', () => {
    const vuln = new Vulnerability({
      id: 'CVE-2024-1234',
      matchReason: MatchReason.VERSION_IN_RANGE,
      matchSources: ['test'],
      description: 'Test',
      cvss: '7.5',
      cvssVer: '3.1',
      exploits: ['http://example.com/exploit'],
    });

    const dict = vuln.toDict();

    expect(dict.id).toBe('CVE-2024-1234');
    expect(dict.match_reason).toBe('version_in_range');
    expect(dict.cvss).toBe('7.5');
    expect(dict.cvss_ver).toBe('3.1');
    expect(dict.exploits).toContain('http://example.com/exploit');
  });
});
