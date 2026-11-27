import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { maskToken, readStoredConfig, writeStoredConfig } from '../src/config.ts';
import { parseArgv } from '../src/commands.ts';
import {
  CLI_VERSION,
  UPDATE_CHECK_TTL_MS,
  checkForCliUpdate,
  compareSemver,
  parseCliTagVersion
} from '../src/version.ts';

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

test('CLI_VERSION matches cli/package.json version', () => {
  const pkgPath = new URL('../package.json', import.meta.url);
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as { version: string };
  assert.equal(CLI_VERSION, pkg.version);
});

test('parses cli-v* tags and compares semver', () => {
  assert.equal(parseCliTagVersion('cli-v1.2.3'), '1.2.3');
  assert.equal(parseCliTagVersion('v1.2.3'), null);
  assert.equal(compareSemver('1.0.1', '1.0.0'), 1);
  assert.equal(compareSemver('1.1.0', '1.0.9'), 1);
  assert.equal(compareSemver('1.0.0', '1.0.0'), 0);
  assert.equal(compareSemver('1.0.0', '1.2.0'), -1);
});

test('throttles update check with 24h cache and writes hint only to stderr', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cem-update-test-'));
  const cachePath = path.join(tmpDir, 'update-check.json');
  let fetchCalls = 0;
  const mockFetch = (async () => {
    fetchCalls++;
    return new Response(
      JSON.stringify([
        { tag_name: 'cli-v1.2.0', html_url: 'https://github.com/XRSec/cloudflare-email-manager/releases/tag/cli-v1.2.0' }
      ]),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  }) as unknown as typeof fetch;

  const stderrLines: string[] = [];
  const mockStderr = {
    write: (chunk: string | Uint8Array) => {
      stderrLines.push(String(chunk));
      return true;
    }
  };

  // 1. Cold cache: fetches and prints update notice to stderr
  await checkForCliUpdate({
    currentVersion: '1.0.0',
    cachePath,
    now: 1_000_000,
    env: {},
    fetchImpl: mockFetch,
    stderr: mockStderr
  });
  assert.equal(fetchCalls, 1);
  assert.match(stderrLines.join(''), /v1\.2\.0/);

  // 2. Warm cache (< 24h): uses cache without fetching
  stderrLines.length = 0;
  await checkForCliUpdate({
    currentVersion: '1.0.0',
    cachePath,
    now: 1_000_000 + UPDATE_CHECK_TTL_MS - 1000,
    env: {},
    fetchImpl: mockFetch,
    stderr: mockStderr
  });
  assert.equal(fetchCalls, 1);
  assert.match(stderrLines.join(''), /v1\.2\.0/);

  // 3. Disabled via CEM_NO_UPDATE_CHECK=1: skips both fetch and stderr
  stderrLines.length = 0;
  await checkForCliUpdate({
    currentVersion: '1.0.0',
    cachePath,
    now: 1_000_000 + UPDATE_CHECK_TTL_MS + 1000,
    env: { CEM_NO_UPDATE_CHECK: '1' },
    fetchImpl: mockFetch,
    stderr: mockStderr
  });
  assert.equal(fetchCalls, 1);
  assert.equal(stderrLines.length, 0);

  // 4. Network failure never throws
  await checkForCliUpdate({
    currentVersion: '1.0.0',
    cachePath,
    now: 1_000_000 + UPDATE_CHECK_TTL_MS + 2000,
    env: {},
    fetchImpl: (async () => {
      throw new Error('network down');
    }) as unknown as typeof fetch,
    stderr: mockStderr
  });

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
