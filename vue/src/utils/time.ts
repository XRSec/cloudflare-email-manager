import { useSystemStore } from '@/composables/system'

const DEFAULT_TIMEZONE = 'Asia/Shanghai'

export const getConfiguredTimeZone = () => {
  const systemStore = useSystemStore()
  const timeZone = systemStore.systemConfig?.timezone?.trim()

  if (!timeZone) {
    return DEFAULT_TIMEZONE
  }

  try {
    new Intl.DateTimeFormat('zh-CN', { timeZone })
    return timeZone
  } catch {
    return DEFAULT_TIMEZONE
  }
}

export const parseUtcDateTime = (value: string) => {
  const normalized = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(value)
    ? `${value.replace(' ', 'T')}Z`
    : value

  return new Date(normalized)
}

export const formatDateTime = (value?: string | number | Date | null, fallback = '未记录') => {
  if (!value) return fallback

  const date = value instanceof Date
    ? value
    : parseUtcDateTime(String(value))

  if (Number.isNaN(date.getTime())) return String(value)

  return date.toLocaleString('zh-CN', {
    timeZone: getConfiguredTimeZone(),
    hour12: false
  })
}

export const getConfiguredTimeZoneLabel = () => getConfiguredTimeZone()
