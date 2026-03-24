import { getCurrentScope, onScopeDispose } from 'vue'

export const TASK_TERMINAL_STATUSES = [
  'completed',
  'download_failed',
  'static_failed',
  'dynamic_failed',
]

export function usePolling(fetchFn, intervalMs = 30000) {
  let timer = null

  const stop = () => {
    if (timer) {
      clearInterval(timer)
      timer = null
    }
  }

  const start = async (immediate = true) => {
    stop()

    if (immediate) {
      await fetchFn()
    }

    timer = setInterval(() => {
      void fetchFn()
    }, intervalMs)
  }

  if (getCurrentScope()) {
    onScopeDispose(stop)
  }

  return { start, stop }
}
