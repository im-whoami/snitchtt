# Snitchtt.ai

Android runtime security detection library. Detects Frida, root, LSPosed, Magisk, hook frameworks, ADB, and tampered build properties — with a hardened native layer that bypasses Java-layer hooks.

---

## Detection coverage

| Category | Checks |
|---|---|
| **Frida** | Agent in maps, memfd JIT heap, zymbiote socket, gadget TCP/symbol, TracerPid, worker threads, late-inject (attach-mode) |
| **Root** | su binary, busybox, Magisk data/mounts/socket, APatch, SELinux permissive, eng build |
| **LSPosed / Xposed** | Daemon process, data dir, module list (LsPosed, Shamiko, HMA, ZGNext), XposedBridge class |
| **Environment** | LD_PRELOAD injection, ptrace blocker, PLT hooks on SSL/libc |
| **Mounts** | tmpfs over APEX conscrypt, Magisk bind-mounts, system RW |
| **ADB (native)** | `init.svc.adbd` via `__system_property_get`, adb_keys file, TCP 5037 in `/proc/net/tcp6` |
| **Build props (native)** | `ro.boot.vbmeta.digest`, `ro.boot.verifiedbootstate`, `ro.build.tags`, `ro.build.type` |
| **Network** | VPN tunnel, HTTP/S proxy |
| **Certificates** | Unknown root CAs in trust store |
| **APK integrity** | DEX SHA-256 hash pinning |

### Architecture

Three separate `.so` files loaded at runtime via `dlopen(RTLD_LOCAL)`:

- `libsna.so` — Frida / timing / thread detection (`sna_e`)
- `libsnb.so` — Root / mount / env / LSPosed / ADB / build detection (`snb_e`)
- `libsnitchtt.so` — JNI bridge; exports only `JNI_OnLoad`

Native ADB and build property checks call `__system_property_get` directly — bypassing any `Settings.Secure` or `android.os.Build` Java hook. All sensitive symbol lookups use direct Linux syscalls to bypass Frida's libc GOT/PLT hooks.

---

## Integration

### 1. Add the dependency

**Via JitPack** (recommended):

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        maven("https://jitpack.io")
    }
}
```

```kotlin
// app/build.gradle.kts
dependencies {
    implementation("com.github.im-whoami:snitchtt:1.0.0")
}
```

**Via local AAR** — copy `snitchtt-1.0.0.aar` into `app/libs/` then:

```kotlin
dependencies {
    implementation(files("libs/snitchtt-1.0.0.aar"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("androidx.core:core-ktx:1.13.1")
}
```

### 2. Register the ContentProvider (auto-init)

The library ships a `SnitchProvider` that loads the native layer before `Application.onCreate()`. Add it to your `AndroidManifest.xml`:

```xml
<provider
    android:name="ai.snitchtt.SnitchProvider"
    android:authorities="${applicationId}.snitchtt_init"
    android:exported="false"
    android:initOrder="2147483647" />
```

> If you are already using the library's AAR this is already merged in. Only needed when using the JAR directly.

### 3. Initialize and scan

```kotlin
// Application.onCreate()
val snitchtt = Snitchtt.init(
    context = this,
    config  = SnitchConfig(
        checkFridaMaps       = true,
        checkFridaTracer     = true,
        checkFridaPort       = true,
        checkFridaStack      = true,
        checkFridaFd         = true,
        checkRoot            = true,
        checkMounts          = true,
        checkPltHooks        = true,
        checkEnv             = true,
        checkXposed          = true,
        checkLsposed         = true,
        checkHma             = true,
        checkAdb             = true,
        checkNetwork         = true,
        checkBuildSpoof      = true,
        checkTimingAnomaly   = true,
        enableContinuousMonitor = true,
        monitorIntervalSeconds  = 15
    )
)
```

```kotlin
// Run a scan (suspend function — call from a coroutine)
lifecycleScope.launch {
    val report = snitchtt.scan()

    if (report.riskScore >= 20) {
        // Kill session / block access
    }

    report.flags.forEach { flag ->
        Log.w("Security", "[${flag.score}] ${flag.name}: ${flag.description}")
    }
}
```

### 4. Continuous monitoring

```kotlin
snitchtt.startMonitoring { report ->
    // Called on IO dispatcher whenever the native monitor thread fires
    if (report.riskScore >= 20) finishAffinity()
}

// Later:
snitchtt.stopMonitoring(listener)
```

### 5. APK DEX hash pinning (optional)

Generate hashes at build time:

```bash
python3 -c "
import zipfile, hashlib, sys
with zipfile.ZipFile(sys.argv[1]) as z:
    for n in sorted(e.filename for e in z.infolist() if e.filename.startswith('classes') and e.filename.endswith('.dex')):
        h = hashlib.sha256(z.read(n)).hexdigest()
        print(f'\"{h}\"')
" app-release.apk
```

Pass them to config:

```kotlin
SnitchConfig(
    checkApkIntegrity = true,
    dexHashes = listOf(
        "abc123...",   // classes.dex
        "def456..."    // classes2.dex
    )
)
```

### 6. Score thresholds (recommended)

| Score | Suggested action |
|---|---|
| 0 | Allow |
| 1–9 | Soft signals (ADB/dev-options) — allow or step-up auth |
| 10–19 | Suspicious — require re-authentication |
| ≥ 20 | Compromised — kill session, block |

---

## ThreatFlag reference

| Flag | Score | Description |
|---|---|---|
| `FRIDA_AGENT_IN_MAPS` | 20 | frida-agent mapped into process memory |
| `FRIDA_HELPER_DELETED` | 20 | frida-helper DEX mapped then deleted |
| `FRIDA_GADGET_SYMBOL` | 20 | frida_gadget_load/gum symbol via dlsym |
| `FRIDA_TRACER_PID` | 20 | TracerPid ≠ 0 |
| `PTRACE_BLOCKED` | 20 | ptrace(TRACEME) blocked |
| `CERT_INJECTION` | 20 | tmpfs over APEX conscrypt |
| `SSL_HOOK_DETECTED` | 20 | SSL_write/read PLT hook |
| `APK_HASH_MISMATCH` | 20 | DEX hash mismatch |
| `FRIDA_LATE_INJECT` | 20 | Frida attached between .so constructor and JNI_OnLoad |
| `LD_PRELOAD_INJECT` | 18 | LD_PRELOAD/LD_LIBRARY_PATH injected |
| `FRIDA_MEMFD_JIT` | 18 | Frida GumJS JIT heap (>8 MB memfd) |
| `FRIDA_ZYMBIOTE_SOCKET` | 18 | Frida spawn-mode zymbiote socket |
| `FRIDA_PORT_FOUND` | 18 | Port responds to Frida D-Bus handshake |
| `FRIDA_MEMFD_FD` | 18 | Frida memfd in /proc/self/fd |
| `FRIDA_THREAD_FOUND` | 15 | Frida worker thread in /proc/self/task |
| `FRIDA_STACK_FRAME` | 15 | Frida frame in native call stack |
| `HOOK_FRAMEWORK_PRESENT` | 15 | Dobby/shadowhook/whale in maps |
| `MAGISK_DATA_FOUND` | 15 | /data/adb/magisk exists |
| `SU_EXEC_SUCCESS` | 15 | su -c id returned uid=0 |
| `XPOSED_CLASS_FOUND` | 12 | XposedBridge in classloader |
| `XPOSED_IN_MAPS` | 12 | xposed/lsposed path in maps |
| `LSPOSED_SOCKET` | 12 | LSPosed IPC socket |
| `LSPOSED_ACTIVE` | 12 | LSPosed daemon/module/DEX |
| `MAGISK_MOUNT` | 12 | Magisk tmpfs on /debug_ramdisk |
| `LIBC_OPEN_HOOK` | 12 | libc open() PLT redirected |
| `FRIDA_GADGET_TCP` | 12 | Unexpected TCP LISTEN port |
| `SYSTEM_RW_MOUNTED` | 10 | System partition read-write |
| `ZYGISK_ACTIVE` | 10 | libzygisk.so from zygote |
| `HMA_ACTIVE` | 10 | PackageManager hook (Hide My Applist) |
| `UNKNOWN_CA_IN_STORE` | 10 | Non-public root CA in trust store |
| `SU_BINARY_FOUND` | 8 | su binary on filesystem |
| `ANONYMOUS_RWX_REGION` | 8 | Anonymous rwxp memory |
| `SELINUX_PERMISSIVE` | 8 | SELinux permissive mode |
| `DEBUG_BUILD_PROPS` | 8 | ro.debuggable=1 or eng/userdebug build |
| `TEST_KEYS_BUILD` | 8 | Build signed with test-keys |
| `TIMING_ANOMALY` | 6 | Syscall timing anomaly |
| `BUILD_METRICS_MISMATCH` | 5 | Hardware metrics ≠ Build.MODEL |
| `ADB_ENABLED` | 5 | USB debugging enabled |
| `BUSYBOX_FOUND` | 4 | BusyBox binary found |
| `DEVELOPER_OPTIONS` | 4 | Developer options enabled |
| `PROXY_CONFIGURED` | 4 | HTTP/S proxy configured |
| `VPN_ACTIVE` | 4 | Active VPN tunnel |
| `VBMETA_DIGEST_CLEARED` | 3 | ro.boot.vbmeta.digest empty |

---

## Requirements

- Android minSdk 24 (Android 7.0)
- compileSdk 35
- ABI: `arm64-v8a`, `armeabi-v7a`, `x86_64`
- Kotlin 2.0 / Java 17

---

## License

MIT + Commons Clause — free to use, modify, fork, and distribute. You **cannot sell** the library itself or a service built primarily around it. Integrating it into your own app (including a paid app) is fine. See [LICENSE](LICENSE).
