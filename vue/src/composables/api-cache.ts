import { cacheService } from './cache'

interface CachedApiOptions {
  forceRefresh?: boolean
  ttl?: number
}

export const API_CACHE_TTL = {
  SYSTEM_CONFIG: 30 * 60 * 1000,
  ROUTING_RULES: 10 * 60 * 1000,
  ROUTING_STATS: 2 * 60 * 1000,
  ROUTING_LOGS: 2 * 60 * 1000
}

export const API_CACHE_KEYS = {
  SYSTEM_CONFIG: 'api:system:config',
  ROUTING_RULES: 'api:routing:rules',
  ROUTING_STATS: 'api:routing:stats',
  routingLogs: (page: number, limit: number) => `api:routing:forward_logs:page_${page}:limit_${limit}`
}

export async function cachedApiRequest<T>(
  key: string,
  ttl: number,
  request: () => Promise<T>,
  options: CachedApiOptions = {}
): Promise<T> {
  if (!options.forceRefresh) {
    const cached = cacheService.get<T>(key)
    if (cached !== undefined) {
      return cached
    }
  }

  const result = await request()
  cacheService.set(key, result, options.ttl || ttl)
  return result
}

export function invalidateApiCache(keys: string[]) {
  keys.forEach((key) => cacheService.delete(key))
}

export function invalidateApiCacheByPrefix(prefix: string) {
  cacheService.keys().forEach((key) => {
    if (key.startsWith(prefix)) {
      cacheService.delete(key)
    }
  })
}
