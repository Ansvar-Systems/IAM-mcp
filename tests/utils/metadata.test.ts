import { describe, it, expect } from 'vitest';
import { generateResponseMetadata } from '../../src/utils/metadata.js';

describe('generateResponseMetadata', () => {
  it('returns iam domain', () => {
    const meta = generateResponseMetadata();
    expect(meta.domain).toBe('iam');
  });
  it('includes NIST and MITRE in data source', () => {
    const meta = generateResponseMetadata();
    expect(meta.data_source).toContain('NIST');
    expect(meta.data_source).toContain('MITRE');
  });
  it('includes disclaimer about not legal advice', () => {
    const meta = generateResponseMetadata();
    expect(meta.disclaimer).toContain('not legal advice');
  });
  it('includes data_age when provided', () => {
    const meta = generateResponseMetadata('2026-02-21T00:00:00Z');
    expect(meta.data_age).toBe('2026-02-21T00:00:00Z');
  });
  it('data_age is undefined when not provided', () => {
    const meta = generateResponseMetadata();
    expect(meta.data_age).toBeUndefined();
  });
});
