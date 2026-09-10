# NativeShieldLab

An independently implemented, offline proof of concept for encrypted Android application DEX, assets, compiled resource tables and resource files. It includes a real React Native **0.68.5 / Hermes 0.11.0 / old-architecture** fixture, not just a Java loader demonstration.

This is an experimental implementation, not a production-ready protector or an integration into an existing business application. No commercial tooling, runtime key server, protection telemetry, ART patching, hidden-API exemptions, AssetManager hooks or proxy-Application replacement are used by this runtime.

## Implemented startup path

1. The output APK contains a small ordinary bootstrap DEX, the normal installable manifest, unchanged host native libraries and AES-256-GCM encrypted payloads. Application DEX and the resource package are encrypted. Android must be able to read the bootstrap and manifest before decryption.
2. On API 29+, Android calls `BootFactory.instantiateClassLoader` before creating application components. It decrypts the application DEX into direct buffers and returns a public `InMemoryDexClassLoader`. API 28 initializes that loader in the component factory's `instantiateApplication` callback instead; later component callbacks and wrapped contexts use the payload loader.
3. The original component factory is loaded from that encrypted DEX and receives the class-loader/Application/provider/activity callbacks. Android instantiates and attaches the real Application normally.
4. On API 30+, a source-level call at the start of the real Application's `attachBaseContext` decrypts the resource package into a process-local anonymous file descriptor (`memfd`). `ResourcesProvider.loadFromApk` and `Resources.addLoaders` expose its resource table and files through Android's resource machinery. No plaintext disk resource cache is created on this path. API 28/29 use the separate legacy path described below.
5. Activity attachment installs the same loader in the Activity's resource context. Providers can read resources before `Application.onCreate`. The RN context and its native asset access can then read the decrypted Hermes bundle through the usual asset mechanism.

This is **real payload encryption**, not merely R8 renaming. It also makes small explicit startup integration changes; it is not currently a drop-in packer for arbitrary APKs.

## Evidence recorded locally

`evidence/static.json` validates the small fixture: two encrypted application DEX payloads, absent plaintext resource table/layouts/assets and absent known plaintext markers. Corruption and cross-entry substitution fail GCM authentication.

`evidence/android15-factory-v2/results.json` and `evidence/android17-factory-v2/results.json` record five cold starts, original factory delegation, real Application identity in early providers, encrypted resource strings/localized strings/layout/raw reads, native asset reads, actual Hermes bytecode execution, persistent data through reinstall, corrupted DEX/resource rejection and valid-build recovery. Version 2 on Android 17 resumed the persisted counter from version 1 despite a fresh per-build encryption key.

`evidence/rn-static.json` records the baseline/protected APK hashes, encrypted application DEX count and byte-for-byte native-library hashes. The complete synthetic RN application's DEX, resource table, resource files and assets are encrypted. The root APK no longer contains `resources.arsc`, `res/` or a readable `assets/index.android.bundle`.

Current RN results are in `evidence/rn-android9-v6/`, `evidence/rn-android10-v6/`, `evidence/rn-android15-v6/` and `evidence/rn-android17-v6/`. Each contains one baseline and five protected cold starts of the same protected APK. Every launch has a unique token to prevent stale process logs from being mistaken for a pass. The JavaScript component mounts through the actual RN bridge and calls a Java native module, which verifies the decrypted English resource, a Hindi configuration context and isolation of that configuration from the original context. UI hierarchies and screenshots corroborate the visible screen.

| Android emulator | API | Kernel page size | Current RN result |
| --- | --- | --- | --- |
| 9 | 28 | 4 KB | Baseline + five protected starts pass |
| 10 | 29 | 4 KB | Baseline + five protected starts pass |
| 15 | 35 | 4 KB | Baseline + five protected starts pass |
| 17 | 37 | 16 KB | Same checks pass in native page-size compatibility mode |

These are arm64 emulator results for the synthetic RN fixture, not a claim of coverage across every Android version, ABI, OEM or application.

`evidence/rn-integrity-android9-v6/results.json` and `evidence/rn-integrity-android17-v6/results.json` additionally verify rejection of individually corrupted DEX/resource ciphertext and successful recovery after restoring the valid build. Corrupted APKs are re-signed with the same disposable fixture key and pass APK signature verification, so the observed `AEADBadTagException` is payload authentication failure. The test uses a live log stream with a unique start marker to exclude old crash records.

Current protected RN APK SHA-256: `23778a86f642955e0a7bbb475c94d4d73851a5b800ffde09fef110bb627926fd`. The report hashes refer to this exact build. This is a test-signed synthetic APK.

**Android 17 qualification:** the installed API 37 emulator has 16 KB pages, but the unchanged RN 0.68.5 native libraries have 4 KB ELF alignment. Android displays a compatibility warning and runs the fixture in page-size compatibility mode. Successful loading there is not proof of native 16 KB compliance. Both baseline and protected builds must be assessed under that qualification. Do not hide the warning and call the binary fixed.

## Experimental Android 9/10 resource path

The API 28/29 context wrapper calls public `PackageManager.getResourcesForApplication(ApplicationInfo)` with a cloned application descriptor pointing at an open process-local file descriptor. Each configuration context retains its own descriptor and resource instance. No framework fields are modified, but the use of a proc-fd path through this API is not a documented compatibility guarantee and needs OEM validation.

A memory-only `memfd` experiment failed on Android 9: SELinux denied reopening the descriptor through `/proc/self/fd`. The failure is preserved in `evidence/rn-android9-v5/` and `build/android9-v5-full.log`. The working route creates an empty app-private file, opens its read/write descriptors, **unlinks it before writing plaintext**, and keeps a read descriptor alive for resource access. It leaves no named plaintext resource cache, but it is **disk-backed**: forensic recovery and access by a compromised process remain possible. It must not be advertised as memory-only encryption.

Android 9 also lacks the in-memory class-loader constructor with a native-library search path. The RN fixture explicitly adds its extracted native-library directory to SoLoader with `RESOLVE_DEPENDENCIES` before RN startup. That fixed the observed intermittent `libjsi.so` dependency failure. Arbitrary libraries using direct `System.loadLibrary` remain an integration concern; the small standalone Hermes fixture has not passed that Android 9 path.

## Important remaining work

- Android 9/10 support is experimental and validated only within the RN fixture described above. API 30+ has the cleaner resource-provider route. Neither path guarantees compatibility with future Android releases.
- Full existing-application integration, third-party native modules, real USB/vehicle sessions, services/receivers/multiprocess behavior, OEM coverage, Android 16 runtime testing and memory/performance qualification remain unfinished.
- The tiny fixture covers multiple DEX files; the current RN fixture produces one application DEX. The actual application's multidex, reflection, serialization and class-loader consumers still require validation.
- All local-key encryption is recoverable by an attacker who obtains the runtime key. This prototype intentionally embeds a plainly recoverable test content key in generated bootstrap code. Key concealment, signing-certificate binding, bootstrap integrity and production hardening are not implemented. No production signing key is involved.
- AES-GCM uses a random 256-bit key per pack and random 96-bit nonces, with version/entry identity authenticated as AAD. It does not currently authenticate the public manifest or bind the whole APK to a signer.
- Large payloads are decrypted in full, with a 128 MiB per-envelope limit. Peak memory, main-thread delay and process lifetime of plaintext must be measured before deployment. The API 30+ resource memfd is not yet sealed against later writes.
- External-process resources such as launcher icons, labels, widgets or notification layouts may require a small public resource set. The fixture deliberately uses a literal label and platform theme. It does not establish that every resource used outside the application can be encrypted transparently.
- `pack_rn_fixture.py` is deliberately restricted to the synthetic fixture package. The fixture's `installIfProtected` helper allows baseline comparisons and is not an acceptable production fail-open policy.
- No RASP/root/ADB/USB blocking has been added. Encryption qualification is independent from runtime environment policy.

## Offline build

Required locally installed tools: Python 3, JDK 17, JDK 11 for the old Gradle fixture, Android SDK platform 35 and 32, Build Tools 35.0.0 and 31.0.0, NDK 21.4.7075529 and 29.0.13113456, Gradle 7.3.3, and cached RN 0.68.5 / Hermes 0.11.0 dependencies. `NSL_NODE_MODULES` points at a local dependency installation. No package installation or download is performed by `build.py`.

```sh
export NSL_NODE_MODULES=/absolute/path/to/node_modules
python3 build.py
python3 test_runtime.py --serial emulator-5580 --label android17-factory-v2
```

The generated `build/fixture-only.p12` is exclusively a disposable fixture signing identity. Its public test password is not a production credential. Content keys and build outputs are ignored by version control.

For the real RN fixture, create the ignored compile-only key stub in `rn-fixture/generated/lab/shield/BuildSecrets.java` (DEX_COUNT=0, ORIGINAL_FACTORY="androidx.core.app.CoreComponentFactory", key returns 32 zero bytes), link `rn-fixture/node_modules` to the local dependencies, and set `rn-fixture/local.properties` to the local Android SDK. The final packer replaces the bootstrap key; the stub is never used to decrypt a protected payload.

From `rn-fixture`, bundle `index.js` with the installed React Native CLI, compile it with the installed Hermes compiler to `app/src/main/assets/index.android.bundle`, and remove the intermediate plaintext JS from that assets directory. Run Gradle 7.3.3 using JDK 11 with `--offline --no-daemon :app:assembleRelease`. Then from the repository root:

```sh
python3 pack_rn_fixture.py
python3 test_rn.py --serial emulator-5582 --label rn-android15
python3 test_rn.py --serial emulator-5580 --label rn-android17
python3 test_rn_integrity.py --serial emulator-5580 --label rn-integrity-android17
```

The RN fixture disables release lint because its lint distribution is not in the offline cache. A successful build is not a lint pass. The RN fixture APK removes INTERNET permission; its JS performs no network requests. The emulator OS may use its own networking. Builds used public dependency files already present locally; no private application code or signing material is included in the fixtures.

## Sources and credits

The implementation uses documented Android platform mechanisms:

- [AppComponentFactory.instantiateClassLoader, API 29](https://developer.android.com/reference/android/app/AppComponentFactory#instantiateClassLoader(java.lang.ClassLoader,android.content.pm.ApplicationInfo))
- [InMemoryDexClassLoader](https://developer.android.com/reference/dalvik/system/InMemoryDexClassLoader)
- [PackageManager.getResourcesForApplication](https://developer.android.com/reference/android/content/pm/PackageManager#getResourcesForApplication(android.content.pm.ApplicationInfo))
- [ResourcesProvider, API 30](https://developer.android.com/reference/android/content/res/loader/ResourcesProvider.html)
- [Resources.addLoaders](https://developer.android.com/reference/android/content/res/Resources#addLoaders(android.content.res.loader.ResourcesLoader...))
- [Android page-size compatibility](https://developer.android.com/guide/practices/page-sizes)

The fixtures use React Native and Hermes from Meta and their dependencies, under their respective licenses. Native asset tests follow the public access pattern in [RN 0.68.5 JSLoader.cpp](https://github.com/facebook/react-native/blob/v0.68.5/ReactAndroid/src/main/jni/react/jni/JSLoader.cpp). No code from the commercial products was obtained or copied. Earlier open-source protector reviews motivated the experiment; this runtime was written independently.
