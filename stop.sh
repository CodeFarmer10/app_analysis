#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="${ROOT_DIR}/run_logs"
SERVICES=(frontend scheduler celery_worker backend)

log() {
  printf '[stop] %s\n' "$*"
}

stop_service() {
  local name="$1"
  local pid_file="${RUN_DIR}/${name}.pid"
  if [[ ! -f "${pid_file}" ]]; then
    log "${name} pid file not found"
    return
  fi

  local pid
  pid="$(cat "${pid_file}" 2>/dev/null || true)"
  if [[ -z "${pid}" ]]; then
    log "${name} empty pid file"
    rm -f "${pid_file}"
    return
  fi

  if ! kill -0 "${pid}" >/dev/null 2>&1; then
    log "${name} not running, remove stale pid=${pid}"
    rm -f "${pid_file}"
    return
  fi

  log "stopping ${name} pid=${pid}"
  kill "${pid}" >/dev/null 2>&1 || true
  for _ in $(seq 1 20); do
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      rm -f "${pid_file}"
      log "${name} stopped"
      return
    fi
    sleep 0.5
  done

  log "${name} still running, force kill pid=${pid}"
  kill -9 "${pid}" >/dev/null 2>&1 || true
  rm -f "${pid_file}"
}

main() {
  for service in "${SERVICES[@]}"; do
    stop_service "${service}"
  done
  log "done"
}

main "$@"
