#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${SCRIPT_DIR}/src/AndroidManifest.xml"
OUTPUT_APK="${SCRIPT_DIR}/DeviceHealthCheck.apk"

AAPT2="${AAPT2:-aapt2}"
ANDROID_JAR="${ANDROID_JAR:-}"
KEYTOOL="${KEYTOOL:-keytool}"
APKSIGNER="${APKSIGNER:-apksigner}"

if [[ -z "${ANDROID_JAR}" ]]; then
    echo "ANDROID_JAR must point to an Android platform android.jar" >&2
    exit 1
fi

for tool in "${AAPT2}" "${KEYTOOL}" "${APKSIGNER}"; do
    if [[ ! -x "${tool}" ]] && ! command -v "${tool}" >/dev/null 2>&1; then
        echo "Required executable not found: ${tool}" >&2
        exit 1
    fi
done

if [[ ! -f "${ANDROID_JAR}" ]]; then
    echo "Android platform jar not found: ${ANDROID_JAR}" >&2
    exit 1
fi

BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/device-health-apk.XXXXXX")"
trap 'rm -rf "${BUILD_DIR}"' EXIT

UNSIGNED_APK="${BUILD_DIR}/DeviceHealthCheck-unsigned.apk"
SIGNED_APK="${BUILD_DIR}/DeviceHealthCheck.apk"
KEYSTORE="${BUILD_DIR}/device-health-build.jks"
KEY_PASSWORD="device-health-build"

"${AAPT2}" link \
    --manifest "${MANIFEST}" \
    -I "${ANDROID_JAR}" \
    --min-sdk-version 23 \
    --target-sdk-version 35 \
    --version-code 1 \
    --version-name 1.0 \
    -o "${UNSIGNED_APK}"

"${KEYTOOL}" -genkeypair \
    -keystore "${KEYSTORE}" \
    -storepass "${KEY_PASSWORD}" \
    -keypass "${KEY_PASSWORD}" \
    -alias device-health-build \
    -dname "CN=Device Health Build, O=Fraud Analysis, C=CN" \
    -keyalg RSA \
    -keysize 2048 \
    -validity 3650 \
    -noprompt

"${APKSIGNER}" sign \
    --ks "${KEYSTORE}" \
    --ks-key-alias device-health-build \
    --ks-pass "pass:${KEY_PASSWORD}" \
    --key-pass "pass:${KEY_PASSWORD}" \
    --v1-signing-enabled true \
    --v2-signing-enabled true \
    --v3-signing-enabled false \
    --v4-signing-enabled false \
    --out "${SIGNED_APK}" \
    "${UNSIGNED_APK}"

"${APKSIGNER}" verify --verbose --min-sdk-version 23 "${SIGNED_APK}"
mv "${SIGNED_APK}" "${OUTPUT_APK}"
echo "Built ${OUTPUT_APK}"
