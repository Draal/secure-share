import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomInt, password, passwordEntropy } from '../public/assets/js/app.js';

test('randomInt stays in range and covers it', () => {
  const seen = new Set();
  for (let i = 0; i < 2000; i++) {
    const n = randomInt(7);
    assert.ok(Number.isInteger(n) && n >= 0 && n < 7);
    seen.add(n);
  }
  assert.equal(seen.size, 7);
});

test('password has the length and every selected set', () => {
  for (let i = 0; i < 200; i++) {
    const p = password({ length: 8, upper: true, lower: true, digits: true, symbols: true });
    assert.equal(p.length, 8);
    for (const re of [/[A-Z]/, /[a-z]/, /[0-9]/, /[!#$%&*+\-=?@^_]/]) assert.match(p, re);
  }
});

test('noSimilar drops look-alike characters', () => {
  const p = password({ length: 64, upper: true, lower: true, digits: true, noSimilar: true });
  assert.doesNotMatch(p, /[0Oo1lI]/);
});

test('entropy of one set is length * log2(alphabet)', () => {
  assert.equal(passwordEntropy({ length: 10, digits: true }), 10 * Math.log2(10));
  const mixed = passwordEntropy({ length: 20, upper: true, lower: true, digits: true, symbols: true });
  assert.ok(mixed < 20 * Math.log2(75) && mixed > 20 * Math.log2(75) - 1);
});
