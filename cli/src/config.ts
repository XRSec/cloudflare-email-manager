import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export interface CemConfig {
  baseUrl: string;
  token: string;
  defaultFrom?: string;
}

export function getConfigPath(): string {
  const home = os.homedir();
  return path.join(home, '.config', 'cem', 'config.json');
}

export function maskToken(token?: string): string {
  if (!token) return '(not set)';
  if (token.length <= 10) return '*'.repeat(token.length);
  return `${token.slice(0, 6)}...${token.slice(-4)}`;
}

export function readStoredConfig(configPath = getConfigPath()): Partial<CemConfig> {
  if (!fs.existsSync(configPath)) {
    return {};
  }
  const raw = fs.readFileSync(configPath, 'utf8');
  const parsed = JSON.parse(raw);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`Invalid config format in ${configPath}`);
  }
  return parsed as Partial<CemConfig>;
}

export function writeStoredConfig(update: Partial<CemConfig>, configPath = getConfigPath()): CemConfig {
  const existing = readStoredConfig(configPath);
  const merged: CemConfig = {
    baseUrl: (update.baseUrl ?? existing.baseUrl ?? '').trim().replace(/\/+$/, ''),
    token: (update.token ?? existing.token ?? '').trim(),
    ...(update.defaultFrom ?? existing.defaultFrom
      ? { defaultFrom: (update.defaultFrom ?? existing.defaultFrom ?? '').trim() }
      : {})
  };

  const dir = path.dirname(configPath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(configPath, JSON.stringify(merged, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(configPath, 0o600);
  return merged;
}

export function resolveConfig(configPath = getConfigPath()): CemConfig {
  const stored = readStoredConfig(configPath);
  const baseUrl = (process.env.CEM_BASE_URL ?? stored.baseUrl ?? '').trim().replace(/\/+$/, '');
  const token = (process.env.CEM_TOKEN ?? stored.token ?? '').trim();
  const defaultFrom = (process.env.CEM_FROM ?? stored.defaultFrom ?? '').trim() || undefined;

  if (!baseUrl) {
    throw new Error('Missing baseUrl. Run `cem config set --base-url <url>` or set CEM_BASE_URL.');
  }
  if (!token) {
    throw new Error('Missing token. Run `cem config set --token <token>` or set CEM_TOKEN.');
  }

  return { baseUrl, token, defaultFrom };
}
