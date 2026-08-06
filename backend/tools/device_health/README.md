# Device Health Check APK

`DeviceHealthCheck.apk` is a minimal, no-code package used only by the standalone
quarantined-device recovery service to verify package installation and removal.
Its package name is `com.fraudanalysis.devicehealth`. It declares no permissions
or Android components.

The complete app source is `src/AndroidManifest.xml`. Rebuild it with Android SDK
Build Tools and a matching platform jar:

```bash
AAPT2=/path/to/aapt2 \
ANDROID_JAR=/path/to/android.jar \
KEYTOOL=/path/to/keytool \
APKSIGNER=/path/to/apksigner \
./build_health_apk.sh
```

The script creates a temporary, non-production signing key, signs with APK
Signature Schemes v1 and v2 (v1 is required by the API 23 minimum), verifies the
signature, and deletes the temporary build directory. Signing keys and Android
build tools must never be committed.
