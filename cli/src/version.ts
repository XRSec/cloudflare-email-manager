import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const CLI_VERSION = '1.0.0';
export const UPDATE_CHECK_TTL_MS = 24 * 60 * 60 * 1000;
export const UPDATE_CHECK_TIMEOUT_MS = 1500;
export const GITHUB_RELEASES_API = 'https://api.github.com/repos/XRSec/cloudflare-email-manager/releases?per_page=10';

export interface UpdateCheckCache {
  checkedAt: number;
  latestVersion: string | null;
  releaseUrl: string | null;
}

export function getUpdateCheckCachePath(): string {
  return path.join(os.homedir(), '.config', 'cem', 'update-check.json');
}

export function parseCliTagVersion(tagName: string): string | null {
  const match = tagName.trim().match(/^cli-v(\d+\.\d+\.\d+)$/);
  return match ? match[1] : null;
}

export function compareSemver(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff > 0 ? 1 : -1;
  }
  return 0;
}

export function formatUpdateNotice(currentVersion: string, latestVersion: string, releaseUrl: string): string {
  return `[cem] New version available: v${latestVersion} (current: v${currentVersion})\n[cem] Download: ${releaseUrl}\n`;
}

function readUpdateCache(cachePath: string): UpdateCheckCache | null {
  try {
    if (!fs.existsSync(cachePath)) return null;
    const raw = fs.readFileSync(cachePath, 'utf8');
    const parsed = JSON.parse(raw) as Partial<UpdateCheckCache>;
    if (typeof parsed.checkedAt !== 'number') return null;
    return {
      checkedAt: parsed.checkedAt,
      latestVersion: typeof parsed.latestVersion === 'string' ? parsed.latestVersion : null,
      releaseUrl: typeof parsed.releaseUrl === 'string' ? parsed.releaseUrl : null
    };
  } catch {
    return null;
  }
}

function writeUpdateCache(cachePath: string, cache: UpdateCheckCache): void {
  try {
    const dir = path.dirname(cachePath);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(cachePath, JSON.stringify(cache, null, 2) + '\n', { mode: 0o600 });
  } catch {
    // Non-blocking: ignore cache write errors
  }
}

export async function fetchLatestCliRelease(
  fetchImpl: typeof fetch = fetch,
  timeoutMs = UPDATE_CHECK_TIMEOUT_MS
): Promise<{ latestVersion: string; releaseUrl: string } | null> {
  const res = await fetchImpl(GITHUB_RELEASES_API, {
    headers: {
      Accept: 'application/vnd.github+json',
      'User-Agent': `cem-cli/${CLI_VERSION}`
    },
    signal: AbortSignal.timeout(timeoutMs)
  });

  if (!res.ok) return null;
  const releases = (await res.json()) as Array<{
    tag_name?: string;
    html_url?: string;
    draft?: boolean;
    prerelease?: boolean;
  }>;
  if (!Array.isArray(releases)) return null;

  let best: { latestVersion: string; releaseUrl: string } | null = null;
  for (const rel of releases) {
    if (rel.draft || rel.prerelease || !rel.tag_name) continue;
    const ver = parseCliTagVersion(rel.tag_name);
    if (!ver) continue;
    if (!best || compareSemver(ver, best.latestVersion) > 0) {
      best = {
        latestVersion: ver,
        releaseUrl: rel.html_url || `https://github.com/XRSec/cloudflare-email-manager/releases/tag/${rel.tag_name}`
      };
    }
  }
  return best;
}

export interface UpdateCheckOptions {
  currentVersion?: string;
  cachePath?: string;
  now?: number;
  ttlMs?: number;
  env?: NodeJS.ProcessEnv;
  fetchImpl?: typeof fetch;
  stderr?: Pick<NodeJS.WriteStream, 'write'>;
}

export async function checkForCliUpdate(options: UpdateCheckOptions = {}): Promise<void> {
  const env = options.env ?? process.env;
  if (env.CEM_NO_UPDATE_CHECK === '1') {
    return;
  }

  const currentVersion = options.currentVersion ?? CLI_VERSION;
  const cachePath = options.cachePath ?? getUpdateCheckCachePath();
  const now = options.now ?? Date.now();
  const ttlMs = options.ttlMs ?? UPDATE_CHECK_TTL_MS;
  const stderr = options.stderr ?? process.stderr;

  try {
    let cache = readUpdateCache(cachePath);
    if (!cache || now - cache.checkedAt >= ttlMs) {
      const latest = await fetchLatestCliRelease(options.fetchImpl ?? fetch);
      cache = {
        checkedAt: now,
        latestVersion: latest?.latestVersion ?? null,
        releaseUrl: latest?.releaseUrl ?? null
      };
      writeUpdateCache(cachePath, cache);
    }

    if (cache.latestVersion && cache.releaseUrl && compareSemver(cache.latestVersion, currentVersion) > 0) {
      stderr.write(formatUpdateNotice(currentVersion, cache.latestVersion, cache.releaseUrl));
    }
  } catch {
    // Non-blocking: network or timeout errors must never interrupt the main command
  }
}
