import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { maskToken, readStoredConfig, writeStoredConfig } from '../src/config.ts';
import { parseArgv } from '../src/commands.ts';

test('masks tokens safely', () => {
  assert.equal(maskToken(undefined), '(not set)');
  assert.equal(maskToken('cem_1234567890abcdef'), 'cem_12...cdef');
});

test('writes and reads config with 0600 permissions', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cem-cli-test-'));
  const cfgPath = path.join(tmpDir, 'config.json');
  writeStoredConfig({ baseUrl: 'https://mail.example.com/', token: 'cem_secret_123456' }, cfgPath);

  const stat = fs.statSync(cfgPath);
  assert.equal(stat.mode & 0o777, 0o600);

  const loaded = readStoredConfig(cfgPath);
  assert.equal(loaded.baseUrl, 'https://mail.example.com');
  assert.equal(loaded.token, 'cem_secret_123456');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('parses CLI flags and positionals', () => {
  const parsed = parseArgv(['list', '--folder', 'inbox', '--limit=50', '--json']);
  assert.deepEqual(parsed.positionals, ['list']);
  assert.equal(parsed.flags.folder, 'inbox');
  assert.equal(parsed.flags.limit, '50');
  assert.equal(parsed.flags.json, true);
});
