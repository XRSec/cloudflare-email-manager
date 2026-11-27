import assert from 'node:assert/strict';
import test from 'node:test';
import { generateApiToken } from '../src/utils/crypto.ts';

test('generates valid api token starting with cem_', () => {
    const token = generateApiToken();
    assert.match(token, /^cem_[0-9a-f]{48}$/);
});

test('generates unique tokens', () => {
    const token1 = generateApiToken();
    const token2 = generateApiToken();
    assert.notEqual(token1, token2);
});
