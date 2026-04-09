const getCurrentTargetUrl = () => {
  const { pathname, search, hash } = window.location
  return `${pathname}${search}${hash}`
}

const ensureLoginUrl = () => {
  if (window.location.pathname === '/login') {
    return
  }

  const targetUrl = getCurrentTargetUrl()
  const nextUrl = `/login?redirect=${encodeURIComponent(targetUrl)}`
  window.history.replaceState(window.history.state, '', nextUrl)
}

const hasStoredUser = () => {
  return !!localStorage.getItem('user_info')
}

async function bootstrap() {
  if (hasStoredUser()) {
    const { mountApp } = await import('./entry/bootstrap-app')
    await mountApp()
    return
  }

  ensureLoginUrl()
  const { mountLoginApp } = await import('./entry/bootstrap-login')
  await mountLoginApp()
}

void bootstrap()
