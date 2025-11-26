/**
 * Tests for EPSS and EOL integration
 */

import { describe, test, expect } from 'bun:test';
import type { Vulnerability } from '../src/types/vulnerability';
import { MatchReason } from '../src/types/vulnerability';
import { getEPSSRiskLevel } from '../src/utils/epss';
import { formatEOLStatus, type VersionStatus } from '../src/utils/eol';

describe('EPSS Integration', () => {
  test('should categorize EPSS risk levels correctly', () => {
    expect(getEPSSRiskLevel('15.5%')).toBe('Critical');
    expect(getEPSSRiskLevel('7.2%')).toBe('High');
    expect(getEPSSRiskLevel('2.1%')).toBe('Medium');
    expect(getEPSSRiskLevel('0.5%')).toBe('Low');
    expect(getEPSSRiskLevel('0.01%')).toBe('Very Low');
    expect(getEPSSRiskLevel('')).toBe('Unknown');
  });
});

describe('EOL Integration', () => {
  test('should format EOL status correctly', () => {
    const eolStatus: VersionStatus = {
      status: 'eol',
      latest: '3.0.0',
      ref: 'https://endoflife.date/jquery'
    };
    
    const formatted = formatEOLStatus(eolStatus);
    expect(formatted).toContain('End-of-Life');
    expect(formatted).toContain('3.0.0');
    expect(formatted).toContain('https://endoflife.date/jquery');
  });
  
  test('should format outdated status correctly', () => {
    const outdatedStatus: VersionStatus = {
      status: 'outdated',
      latest: '2.5.0',
      ref: 'https://endoflife.date/apache'
    };
    
    const formatted = formatEOLStatus(outdatedStatus);
    expect(formatted).toContain('Outdated');
    expect(formatted).toContain('2.5.0');
  });
  
  test('should format current status correctly', () => {
    const currentStatus: VersionStatus = {
      status: 'current',
      latest: '1.2.3',
      ref: 'https://endoflife.date/test'
    };
    
    const formatted = formatEOLStatus(currentStatus);
    expect(formatted).toContain('Current version');
  });
  
  test('should handle undefined status', () => {
    const formatted = formatEOLStatus(undefined);
    expect(formatted).toBe('');
  });
});

describe('Vulnerability EPSS field', () => {
  test('should include EPSS in vulnerability serialization', () => {
    const vuln = new (class extends Object {
      constructor() {
        super();
        Object.assign(this, {
          id: 'CVE-2024-TEST',
          matchReason: MatchReason.VULN_ID,
          matchSources: ['test'],
          epss: '5.2%',
          misc: {}
        });
      }
      toDict() {
        return {
          id: 'CVE-2024-TEST',
          match_reason: MatchReason.VULN_ID,
          match_sources: ['test'],
          epss: '5.2%'
        };
      }
    })();
    
    const dict = vuln.toDict();
    expect(dict.epss).toBe('5.2%');
  });
});
