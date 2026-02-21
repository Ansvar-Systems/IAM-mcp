import { describe, it, expect } from 'vitest';
import { sanitizeFtsInput, buildFtsQueryVariants } from '../../src/utils/fts-query.js';

describe('sanitizeFtsInput', () => {
  it('strips FTS5 special characters', () => {
    expect(sanitizeFtsInput('CWE-287*')).toBe('CWE 287');
  });
  it('preserves alphanumeric and spaces', () => {
    expect(sanitizeFtsInput('brute force attack')).toBe('brute force attack');
  });
  it('collapses multiple spaces', () => {
    expect(sanitizeFtsInput('  spaced   out  ')).toBe('spaced out');
  });
  it('handles empty string', () => {
    expect(sanitizeFtsInput('')).toBe('');
  });
  it('strips all special chars', () => {
    expect(sanitizeFtsInput('"hello" (world) [test] {foo} ^bar ~baz')).toBe('hello world test foo bar baz');
  });
});

describe('buildFtsQueryVariants', () => {
  it('returns phrase match first for multi-word', () => {
    const v = buildFtsQueryVariants('brute force');
    expect(v[0]).toBe('"brute force"');
  });
  it('returns AND query second for multi-word', () => {
    const v = buildFtsQueryVariants('brute force');
    expect(v[1]).toBe('brute AND force');
  });
  it('returns prefix query third for multi-word', () => {
    const v = buildFtsQueryVariants('brute force');
    expect(v[2]).toBe('brute AND force*');
  });
  it('returns single term then prefix for single word', () => {
    const v = buildFtsQueryVariants('RBAC');
    expect(v[0]).toBe('RBAC');
    expect(v[1]).toBe('RBAC*');
  });
  it('does not add prefix for short single terms', () => {
    const v = buildFtsQueryVariants('MF');
    expect(v).toEqual(['MF']);
  });
  it('returns empty for empty input', () => {
    expect(buildFtsQueryVariants('')).toEqual([]);
  });
  it('returns empty for whitespace-only input', () => {
    expect(buildFtsQueryVariants('   ')).toEqual([]);
  });
});
