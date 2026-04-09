import { errorLog } from '../utils/debug';
import type { D1Database } from '../types';

export type ChangeSignalKey = 'emails' | 'dashboard' | 'forward_logs' | 'routing_config' | 'system_config';

export type ChangeSignals = Record<ChangeSignalKey, number> & {
    updated_at: string;
};

const DEFAULT_SIGNALS: ChangeSignals = {
    emails: 0,
    dashboard: 0,
    forward_logs: 0,
    routing_config: 0,
    system_config: 0,
    updated_at: ''
};

export async function getChangeSignals(db?: D1Database): Promise<ChangeSignals> {
    if (!db) {
        return { ...DEFAULT_SIGNALS };
    }

    try {
        const result = await db.prepare(`
            SELECT key, version, updated_at
            FROM change_signals
        `).all();

        const signals = { ...DEFAULT_SIGNALS };
        for (const row of result.results || []) {
            const key = row.key as ChangeSignalKey;
            if (key in DEFAULT_SIGNALS) {
                signals[key] = Number(row.version) || 0;
                const updatedAt = typeof row.updated_at === 'string' ? row.updated_at : '';
                if (updatedAt && (!signals.updated_at || updatedAt > signals.updated_at)) {
                    signals.updated_at = updatedAt;
                }
            }
        }

        return signals;
    } catch (error) {
        errorLog('[变更信号] 读取失败:', error);
        return { ...DEFAULT_SIGNALS };
    }
}

export async function bumpChangeSignals(db: D1Database | undefined, keys: ChangeSignalKey[]): Promise<void> {
    if (!db || keys.length === 0) return;

    try {
        const version = Date.now();
        const updatedAt = new Date(version).toISOString();

        const uniqueKeys = Array.from(new Set(keys));
        const statements = uniqueKeys.map((key) =>
            db.prepare(`
                INSERT INTO change_signals (key, version, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    version = excluded.version,
                    updated_at = excluded.updated_at
            `).bind(key, version, updatedAt)
        );

        await db.batch(statements);
    } catch (error) {
        errorLog('[变更信号] 更新失败:', error);
    }
}
