#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="$(basename "${ROOT_DIR}")"
PROJECT_PARENT="$(dirname "${ROOT_DIR}")"
OFFLINE_DIR="${OFFLINE_DIR:-${ROOT_DIR}/offline_packages}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUTPUT_FILE="${OUTPUT_FILE:-${PROJECT_PARENT}/${PROJECT_NAME}_offline_${TIMESTAMP}.tar.gz}"

log() {
  printf '[package-offline] %s\n' "$*"
}

die() {
  log "ERROR: $*"
  exit 1
}

canonical_output_file() {
  local output_dir
  local output_name

  output_dir="$(dirname "${OUTPUT_FILE}")"
  output_name="$(basename "${OUTPUT_FILE}")"
  mkdir -p "${output_dir}"
  output_dir="$(cd "${output_dir}" && pwd)"
  printf '%s/%s\n' "${output_dir}" "${output_name}"
}

validate_offline_environment() {
  [[ -f "${OFFLINE_DIR}/runtime/environment.meta" ]] || \
    die "offline metadata not found; run ./installl_online.sh first"
  [[ -x "${OFFLINE_DIR}/runtime/python/bin/python3" ]] || \
    die "offline Python runtime not found"
  [[ -x "${OFFLINE_DIR}/runtime/node/bin/node" ]] || \
    die "offline Node.js runtime not found"
  [[ -x "${OFFLINE_DIR}/backend/.venv/bin/python" ]] || \
    die "offline backend virtual environment not found"
  [[ -d "${OFFLINE_DIR}/frontend/node_modules" ]] || \
    die "offline frontend dependencies not found"
}

write_checksum() {
  local archive="$1"

  if command -v sha256sum >/dev/null 2>&1; then
    (
      cd "$(dirname "${archive}")"
      sha256sum "$(basename "${archive}")" >"$(basename "${archive}").sha256"
    )
  elif command -v shasum >/dev/null 2>&1; then
    (
      cd "$(dirname "${archive}")"
      shasum -a 256 "$(basename "${archive}")" >"$(basename "${archive}").sha256"
    )
  else
    log "sha256sum/shasum not found; checksum was not generated"
  fi
}

main() {
  local archive

  validate_offline_environment
  archive="$(canonical_output_file)"
  case "${archive}" in
    "${ROOT_DIR}"/*) die "OUTPUT_FILE must be outside the project directory" ;;
  esac

  log "creating ${archive}"
  tar -czf "${archive}" \
    --exclude="${PROJECT_NAME}/.git" \
    --exclude="${PROJECT_NAME}/.install_cache" \
    --exclude="${PROJECT_NAME}/.runtime" \
    --exclude="${PROJECT_NAME}/backend/.venv" \
    --exclude="${PROJECT_NAME}/frontend/node_modules" \
    --exclude="${PROJECT_NAME}/run_logs" \
    -C "${PROJECT_PARENT}" "${PROJECT_NAME}"

  write_checksum "${archive}"
  log "package complete: ${archive}"
  log "size: $(du -h "${archive}" | awk '{print $1}')"
}

main "$@"
