import { describe, it, expect } from 'vitest';
import { STRINGS } from '../src/i18n';

describe('i18n completeness', () => {
  it('every key present in English is also present in Persian', () => {
    const enKeys = Object.keys(STRINGS.en).sort();
    const faKeys = Object.keys(STRINGS.fa).sort();
    expect(faKeys).toEqual(enKeys);
  });
});
