#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="${ROOT_DIR}/backend"
FRONTEND_DIR="${ROOT_DIR}/frontend"
RUNTIME_DIR="${ROOT_DIR}/.runtime"
CACHE_DIR="${INSTALL_CACHE_DIR:-${ROOT_DIR}/.install_cache}"
PYTHON_VERSION="${PYTHON_VERSION:-3.13.12}"
NODE_VERSION="${NODE_VERSION:-22.22.1}"
PYTHON_DOWNLOAD_URL="${PYTHON_DOWNLOAD_URL:-https://mirrors.huaweicloud.com/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz}"
PYPI_INDEX_URL="${PYPI_INDEX_URL:-https://pypi.tuna.tsinghua.edu.cn/simple}"
PYPI_FALLBACK_INDEX_URL="${PYPI_FALLBACK_INDEX_URL:-https://pypi.org/simple}"
NODE_DOWNLOAD_BASE_URL="${NODE_DOWNLOAD_BASE_URL:-https://registry.npmmirror.com/-/binary/node}"
NPM_REGISTRY_URL="${NPM_REGISTRY_URL:-https://registry.npmmirror.com}"
NPM_FALLBACK_REGISTRY_URL="${NPM_FALLBACK_REGISTRY_URL:-https://registry.npmjs.org}"
PYTHON_DIR="${RUNTIME_DIR}/python"
NODE_DIR="${RUNTIME_DIR}/node"
VENV_DIR="${BACKEND_DIR}/.venv"
OFFLINE_EXPORT_DIR="${OFFLINE_EXPORT_DIR:-${ROOT_DIR}/offline_packages}"

log() {
  printf '[install-online] %s\n' "$*"
}

die() {
  log "ERROR: $*"
  exit 1
}

run_as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    die "root privileges or sudo are required to install build tools"
  fi
}

download() {
  local output="$1"
  local url
  shift

  if [[ -f "${output}" ]]; then
    log "using cached file: ${output}"
    return
  fi

  for url in "$@"; do
    log "downloading ${url}"
    if command -v curl >/dev/null 2>&1; then
      if curl -fL --retry 3 --connect-timeout 15 -o "${output}" "${url}"; then
        return
      fi
    elif command -v wget >/dev/null 2>&1; then
      if wget -O "${output}" "${url}"; then
        return
      fi
    else
      die "curl or wget is required"
    fi
    rm -f "${output}"
    log "download failed; trying the next URL"
  done

  die "all download URLs failed"
}

install_build_tools() {
  if [[ "${SKIP_BUILD_TOOLS:-0}" == "1" ]]; then
    log "skipping build tools because SKIP_BUILD_TOOLS=1"
    return
  fi

  if command -v dnf >/dev/null 2>&1; then
    log "installing Python build tools with dnf"
    run_as_root dnf install -y gcc gcc-c++ make curl tar gzip xz \
      openssl-devel bzip2-devel libffi-devel zlib-devel xz-devel \
      readline-devel sqlite-devel ncurses-devel gdbm-devel uuid-devel
  elif command -v yum >/dev/null 2>&1; then
    log "installing Python build tools with yum"
    run_as_root yum install -y gcc gcc-c++ make curl tar gzip xz \
      openssl-devel bzip2-devel libffi-devel zlib-devel xz-devel \
      readline-devel sqlite-devel ncurses-devel gdbm-devel libuuid-devel
  elif command -v apt-get >/dev/null 2>&1; then
    log "installing Python build tools with apt-get"
    run_as_root apt-get update
    run_as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y \
      build-essential curl ca-certificates tar gzip xz-utils \
      libssl-dev libbz2-dev libffi-dev zlib1g-dev liblzma-dev \
      libreadline-dev libsqlite3-dev libncurses-dev libgdbm-dev uuid-dev
  else
    die "dnf, yum or apt-get is required to install Python build tools"
  fi
}

node_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'x64\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    *) die "unsupported CPU architecture: $(uname -m)" ;;
  esac
}

install_python() {
  local archive="${CACHE_DIR}/Python-${PYTHON_VERSION}.tgz"
  local source_dir="${CACHE_DIR}/Python-${PYTHON_VERSION}"
  local jobs="${BUILD_JOBS:-}"

  if [[ -x "${PYTHON_DIR}/bin/python3" ]] && \
     [[ "$("${PYTHON_DIR}/bin/python3" -c 'import platform; print(platform.python_version())')" == "${PYTHON_VERSION}" ]]; then
    log "Python ${PYTHON_VERSION} is already installed"
    return
  fi

  download "${archive}" \
    "${PYTHON_DOWNLOAD_URL}" \
    "https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz"
  rm -rf "${source_dir}" "${PYTHON_DIR}"
  tar -xzf "${archive}" -C "${CACHE_DIR}"

  if [[ -z "${jobs}" ]]; then
    jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '2')"
  fi

  log "building Python ${PYTHON_VERSION}"
  (
    cd "${source_dir}"
    ./configure --prefix="${PYTHON_DIR}" --with-ensurepip=install
    make -j "${jobs}"
    make install
  )
  "${PYTHON_DIR}/bin/python3" --version
}

install_backend() {
  log "creating backend virtual environment"
  rm -rf "${VENV_DIR}"
  "${PYTHON_DIR}/bin/python3" -m venv --copies "${VENV_DIR}"

  log "installing backend dependencies from ${PYPI_INDEX_URL}"
  if "${VENV_DIR}/bin/python" -m pip install \
      --index-url "${PYPI_INDEX_URL}" --upgrade pip setuptools wheel && \
     "${VENV_DIR}/bin/python" -m pip install \
      --index-url "${PYPI_INDEX_URL}" -r "${BACKEND_DIR}/requirements.txt"; then
    return
  fi

  log "PyPI mirror failed; retrying with ${PYPI_FALLBACK_INDEX_URL}"
  "${VENV_DIR}/bin/python" -m pip install \
    --index-url "${PYPI_FALLBACK_INDEX_URL}" --upgrade pip setuptools wheel
  "${VENV_DIR}/bin/python" -m pip install \
    --index-url "${PYPI_FALLBACK_INDEX_URL}" -r "${BACKEND_DIR}/requirements.txt"
}

install_node() {
  local arch
  local archive
  local extracted_dir

  arch="$(node_arch)"
  archive="${CACHE_DIR}/node-v${NODE_VERSION}-linux-${arch}.tar.xz"
  extracted_dir="${CACHE_DIR}/node-v${NODE_VERSION}-linux-${arch}"

  if [[ -x "${NODE_DIR}/bin/node" ]] && \
     [[ "$("${NODE_DIR}/bin/node" --version)" == "v${NODE_VERSION}" ]]; then
    log "Node.js ${NODE_VERSION} is already installed"
    return
  fi

  download "${archive}" \
    "${NODE_DOWNLOAD_BASE_URL}/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${arch}.tar.xz" \
    "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${arch}.tar.xz"
  rm -rf "${extracted_dir}" "${NODE_DIR}"
  tar -xJf "${archive}" -C "${CACHE_DIR}"
  mv "${extracted_dir}" "${NODE_DIR}"
  "${NODE_DIR}/bin/node" --version
}

install_frontend() {
  log "installing frontend dependencies from ${NPM_REGISTRY_URL}"
  rm -rf "${FRONTEND_DIR}/node_modules"
  if (
    cd "${FRONTEND_DIR}"
    PATH="${NODE_DIR}/bin:${PATH}" "${NODE_DIR}/bin/npm" ci \
      --registry="${NPM_REGISTRY_URL}"
  ); then
    return
  fi

  log "npm mirror failed; retrying with ${NPM_FALLBACK_REGISTRY_URL}"
  rm -rf "${FRONTEND_DIR}/node_modules"
  (
    cd "${FRONTEND_DIR}"
    PATH="${NODE_DIR}/bin:${PATH}" "${NODE_DIR}/bin/npm" ci \
      --registry="${NPM_FALLBACK_REGISTRY_URL}"
  )
}

write_environment_metadata() {
  cat >"${RUNTIME_DIR}/environment.meta" <<EOF
os=$(uname -s)
arch=$(uname -m)
python=${PYTHON_VERSION}
node=${NODE_VERSION}
source_root=${ROOT_DIR}
EOF
}

export_offline_environment() {
  local export_dir
  export_dir="$(mkdir -p "${OFFLINE_EXPORT_DIR}" && cd "${OFFLINE_EXPORT_DIR}" && pwd)"
  [[ "${export_dir}" != "${ROOT_DIR}" ]] || die "OFFLINE_EXPORT_DIR cannot be the project root"

  log "copying the offline environment to ${export_dir}"
  rm -rf "${export_dir}/runtime" "${export_dir}/backend" "${export_dir}/frontend"
  mkdir -p "${export_dir}/runtime" "${export_dir}/backend" "${export_dir}/frontend"
  cp -a "${PYTHON_DIR}" "${export_dir}/runtime/python"
  cp -a "${NODE_DIR}" "${export_dir}/runtime/node"
  cp -a "${RUNTIME_DIR}/environment.meta" "${export_dir}/runtime/environment.meta"
  cp -a "${VENV_DIR}" "${export_dir}/backend/.venv"
  cp -a "${FRONTEND_DIR}/node_modules" "${export_dir}/frontend/node_modules"
}

main() {
  [[ "$(uname -s)" == "Linux" ]] || die "this installer must run on Linux"
  [[ -f "${BACKEND_DIR}/requirements.txt" ]] || die "backend/requirements.txt not found"
  [[ -f "${FRONTEND_DIR}/package-lock.json" ]] || die "frontend/package-lock.json not found"

  mkdir -p "${RUNTIME_DIR}" "${CACHE_DIR}"
  install_build_tools
  install_python
  install_backend
  install_node
  install_frontend
  write_environment_metadata
  export_offline_environment

  log "installation complete"
  log "offline environment prepared at ${OFFLINE_EXPORT_DIR}"
  log "run ./package_offline.sh to create the transfer archive"
}

main "$@"
