#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="${ROOT_DIR}/backend"
FRONTEND_DIR="${ROOT_DIR}/frontend"
RUN_DIR="${ROOT_DIR}/run_logs"
PYTHON_BIN="${PYTHON_BIN:-${BACKEND_DIR}/.venv/bin/python}"
LOCAL_NODE_BIN="${ROOT_DIR}/.runtime/node/bin"
if [[ -x "${LOCAL_NODE_BIN}/npm" ]]; then
  NPM_BIN="${NPM_BIN:-${LOCAL_NODE_BIN}/npm}"
else
  NPM_BIN="${NPM_BIN:-$(command -v npm 2>/dev/null || true)}"
fi
BACKEND_HOST="${BACKEND_HOST:-0.0.0.0}"
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_HOST="${FRONTEND_HOST:-0.0.0.0}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"
CELERY_CONCURRENCY="${CELERY_CONCURRENCY:-10}"

log() {
  printf '[start] %s\n' "$*"
}

ensure_runtime() {
  if [[ ! -x "${PYTHON_BIN}" ]]; then
    log "backend python not found: ${PYTHON_BIN}"
    log "run ./installl_online.sh or ./install_offline.sh first"
    exit 1
  fi
  if [[ -z "${NPM_BIN}" || ! -x "${NPM_BIN}" ]]; then
    log "npm not found: ${NPM_BIN:-unset}"
    exit 1
  fi
  if [[ ! -d "${FRONTEND_DIR}/node_modules" ]]; then
    log "frontend node_modules not found; run install script first"
    exit 1
  fi
  mkdir -p "${RUN_DIR}"
  if [[ -d "${LOCAL_NODE_BIN}" ]]; then
    export PATH="${LOCAL_NODE_BIN}:${PATH}"
  fi
}

is_running() {
  local pid_file="$1"
  [[ -f "${pid_file}" ]] && kill -0 "$(cat "${pid_file}")" >/dev/null 2>&1
}

start_process() {
  local name="$1"
  local pid_file="${RUN_DIR}/${name}.pid"
  local log_file="${RUN_DIR}/${name}.log"
  shift

  if is_running "${pid_file}"; then
    log "${name} already running, pid=$(cat "${pid_file}")"
    return
  fi

  log "starting ${name}"
  (
    cd "$1"
    shift
    nohup "$@" >"${log_file}" 2>&1 &
    echo $! >"${pid_file}"
  )
  log "${name} pid=$(cat "${pid_file}") log=${log_file}"
}

main() {
  ensure_runtime
  start_process backend "${BACKEND_DIR}" \
    "${PYTHON_BIN}" -m uvicorn main:app --host "${BACKEND_HOST}" --port "${BACKEND_PORT}" --app-dir "${BACKEND_DIR}"
  start_process celery_worker "${BACKEND_DIR}" \
    "${PYTHON_BIN}" -m celery -A workers.celery_app worker --loglevel=info -c "${CELERY_CONCURRENCY}"
  start_process scheduler "${BACKEND_DIR}" \
    "${PYTHON_BIN}" -m workers.scheduler
  start_process frontend "${FRONTEND_DIR}" \
    "${NPM_BIN}" run dev -- --host "${FRONTEND_HOST}" --port "${FRONTEND_PORT}"
  log "done"
}

main "$@"
