#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="${ROOT_DIR}/backend"
FRONTEND_DIR="${ROOT_DIR}/frontend"
RUNTIME_DIR="${ROOT_DIR}/.runtime"
OFFLINE_DIR="${OFFLINE_DIR:-${ROOT_DIR}/offline_packages}"
SOURCE_RUNTIME_DIR="${OFFLINE_DIR}/runtime"
SOURCE_VENV_DIR="${OFFLINE_DIR}/backend/.venv"
SOURCE_NODE_MODULES_DIR="${OFFLINE_DIR}/frontend/node_modules"

log() {
  printf '[install-offline] %s\n' "$*"
}

die() {
  log "ERROR: $*"
  exit 1
}

metadata_value() {
  local key="$1"
  sed -n "s/^${key}=//p" "${SOURCE_RUNTIME_DIR}/environment.meta" | head -n 1
}

validate_offline_environment() {
  local source_os
  local source_arch

  [[ "$(uname -s)" == "Linux" ]] || die "this installer must run on Linux"
  [[ -f "${SOURCE_RUNTIME_DIR}/environment.meta" ]] || \
    die "missing ${SOURCE_RUNTIME_DIR}/environment.meta"
  [[ -x "${SOURCE_RUNTIME_DIR}/python/bin/python3" ]] || \
    die "missing offline Python runtime"
  [[ -x "${SOURCE_RUNTIME_DIR}/node/bin/node" ]] || \
    die "missing offline Node.js runtime"
  [[ -x "${SOURCE_VENV_DIR}/bin/python" ]] || \
    die "missing offline backend virtual environment"
  [[ -d "${SOURCE_NODE_MODULES_DIR}" ]] || \
    die "missing offline frontend node_modules"

  source_os="$(metadata_value os)"
  source_arch="$(metadata_value arch)"
  [[ "${source_os}" == "$(uname -s)" ]] || \
    die "OS mismatch: package=${source_os}, current=$(uname -s)"
  [[ "${source_arch}" == "$(uname -m)" ]] || \
    die "CPU architecture mismatch: package=${source_arch}, current=$(uname -m)"
}

copy_environment() {
  log "copying Python and Node.js runtimes"
  rm -rf "${RUNTIME_DIR}"
  mkdir -p "${RUNTIME_DIR}"
  cp -a "${SOURCE_RUNTIME_DIR}/python" "${RUNTIME_DIR}/python"
  cp -a "${SOURCE_RUNTIME_DIR}/node" "${RUNTIME_DIR}/node"
  cp -a "${SOURCE_RUNTIME_DIR}/environment.meta" "${RUNTIME_DIR}/environment.meta"

  log "copying backend virtual environment"
  rm -rf "${BACKEND_DIR}/.venv"
  cp -a "${SOURCE_VENV_DIR}" "${BACKEND_DIR}/.venv"

  log "copying frontend dependencies"
  rm -rf "${FRONTEND_DIR}/node_modules"
  cp -a "${SOURCE_NODE_MODULES_DIR}" "${FRONTEND_DIR}/node_modules"
}

relocate_virtual_environment() {
  local source_root
  local old_venv
  local new_venv="${BACKEND_DIR}/.venv"

  source_root="$(metadata_value source_root)"
  old_venv="${source_root}/backend/.venv"

  if [[ "${source_root}" != "${ROOT_DIR}" ]]; then
    log "relocating backend virtual environment to ${ROOT_DIR}"
    sed -i.bak \
      -e "s|${source_root}/.runtime/python|${ROOT_DIR}/.runtime/python|g" \
      -e "s|${old_venv}|${new_venv}|g" \
      "${new_venv}/pyvenv.cfg"
    rm -f "${new_venv}/pyvenv.cfg.bak"

    while IFS= read -r -d '' script; do
      if head -n 1 "${script}" 2>/dev/null | grep -Fq "${old_venv}"; then
        sed -i.bak "1s|${old_venv}|${new_venv}|" "${script}"
        rm -f "${script}.bak"
      fi
    done < <(find "${new_venv}/bin" -maxdepth 1 -type f -print0)
  fi
}

verify_environment() {
  local expected_python
  local expected_node

  expected_python="$(metadata_value python)"
  expected_node="$(metadata_value node)"

  [[ "$("${BACKEND_DIR}/.venv/bin/python" -c 'import platform; print(platform.python_version())')" == "${expected_python}" ]] || \
    die "backend Python verification failed"
  [[ "$("${RUNTIME_DIR}/node/bin/node" --version)" == "v${expected_node}" ]] || \
    die "Node.js verification failed"

  "${BACKEND_DIR}/.venv/bin/python" -c 'import fastapi, celery, androguard'
  PATH="${RUNTIME_DIR}/node/bin:${PATH}" \
    "${RUNTIME_DIR}/node/bin/npm" --prefix "${FRONTEND_DIR}" ls --depth=0 >/dev/null
}

main() {
  validate_offline_environment
  copy_environment
  relocate_virtual_environment
  verify_environment
  log "offline environment copied and verified"
}

main "$@"
