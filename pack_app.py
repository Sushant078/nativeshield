#!/usr/bin/env python3
"""Offline packer for React Native Android apps.

Input must be a release APK already built with the shield integration (manifest
appComponentFactory=lab.shield.BootFactory and a React Native bundle hook that calls
lab.shield.BundleLoader. DEX and the Hermes bundle are encrypted; Android resources
and other assets remain plaintext in V1. Nothing here touches the network.
"""
import argparse, os, platform, re, secrets, shutil, subprocess, zipfile, pathlib

ROOT = pathlib.Path(__file__).resolve().parent
SDK = pathlib.Path(os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
                   or os.path.expanduser("~/Library/Android/sdk"))
JAVA_HOME = pathlib.Path(os.environ["JAVA_HOME"])

def ndk_host_tag():
    """NDK prebuilt-toolchain directory name for the current host OS."""
    s = platform.system()
    tag = {"Darwin": "darwin-x86_64", "Linux": "linux-x86_64", "Windows": "windows-x86_64"}.get(s)
    if not tag:
        raise SystemExit(f"unsupported host OS for NDK toolchain: {s}")
    return tag

def exe(name):
    """SDK/NDK CLI tools carry a .bat/.cmd suffix on Windows."""
    return name + (".bat" if platform.system() == "Windows" else "")

ABI_TRIPLE = {
    "arm64-v8a": "aarch64-linux-android",
    "armeabi-v7a": "armv7a-linux-androideabi",
    "x86": "i686-linux-android",
    "x86_64": "x86_64-linux-android",
}

def run(*a, **k):
    subprocess.run([str(x) for x in a], check=True, **k)

def dexkey(n):
    return 1 if n == "classes.dex" else int(n[len("classes"):-len(".dex")])

def _act(v, default):
    """Map an environment action to 0=off, 1=report, or 2=enforce."""
    if v is None:
        return default
    actions = {"off": 0, "none": 0, "0": 0,
               "report": 1, "log": 1, "1": 1,
               "enforce": 2, "block": 2, "2": 2}
    normalized = v.strip().lower()
    if normalized not in actions:
        raise SystemExit(f"invalid RASP action {v!r}; use off, report, or enforce")
    return actions[normalized]

def _bool_env(name, default=True):
    v = os.environ.get(name)
    if v is None:
        return default
    normalized = v.strip().lower()
    if normalized in ("1", "on", "true", "yes"):
        return True
    if normalized in ("0", "off", "false", "no"):
        return False
    raise SystemExit(f"invalid boolean for {name}: {v!r}")

def rasp_config_from_env():
    """Resolve the build-time RASP policy.

    Per-category variables override SHIELD_RASP_MODE. Defaults enforce
    Frida/debugger detections and report root/emulator detections.
    """
    enabled = _bool_env("SHIELD_RASP", True)
    mode = os.environ.get("SHIELD_RASP_MODE")
    mode_val = _act(mode, None) if mode else None
    d_frida = d_debug = 2
    d_root = d_emu = 1
    if mode_val is not None:
        d_frida = d_debug = d_root = d_emu = mode_val
    period_ms = int(os.environ.get("SHIELD_RASP_PERIOD_MS", "3000") or "3000")
    if period_ms < 250 or period_ms > 3600000:
        raise SystemExit("SHIELD_RASP_PERIOD_MS must be between 250 and 3600000")
    return {
        "enabled": enabled,
        "frida": _act(os.environ.get("SHIELD_RASP_FRIDA"), d_frida),
        "debug": _act(os.environ.get("SHIELD_RASP_DEBUG"), d_debug),
        "root": _act(os.environ.get("SHIELD_RASP_ROOT"), d_root),
        "emulator": _act(os.environ.get("SHIELD_RASP_EMULATOR"), d_emu),
        "periodic": _bool_env("SHIELD_RASP_PERIODIC", True),
        "period_ms": period_ms,
        "crypto_gate": _bool_env("SHIELD_RASP_CRYPTO_GATE", True),
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--keystore", required=True)
    ap.add_argument("--alias", required=True)
    ap.add_argument("--storepass", required=True)
    ap.add_argument("--keypass", required=True)
    ap.add_argument("--cert-sha256", help="hex SHA-256 of the signing cert; auto-derived from the keystore if omitted")
    ap.add_argument("--label", default="dev.nativeshield:v1")
    ap.add_argument("--original-factory", default="android.app.AppComponentFactory",
                    help="factory BootFactory delegates to; the framework base survives R8")
    ap.add_argument("--build-tools", default="35.0.0")
    ap.add_argument("--platform", default="android-32")
    ap.add_argument("--ndk", required=True)
    ap.add_argument("--min-sdk", type=int, default=30)
    ap.add_argument("--shares", type=int, default=4)
    args = ap.parse_args()

    if args.min_sdk < 30:
        raise SystemExit("NativeShield V1 requires --min-sdk 30 or newer")
    if not 2 <= args.shares <= 32:
        raise SystemExit("--shares must be between 2 and 32")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", args.label):
        raise SystemExit("--label must be 1-128 ASCII letters, digits, dot, underscore, colon, or hyphen")
    if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*",
                        args.original_factory):
        raise SystemExit("--original-factory must be a fully qualified Java class name")

    BT = SDK / "build-tools" / args.build_tools
    ANDROID_JAR = SDK / "platforms" / args.platform / "android.jar"
    NDK = pathlib.Path(args.ndk)
    tc = NDK / "toolchains/llvm/prebuilt" / ndk_host_tag() / "bin"
    javac = JAVA_HOME / "bin/javac"
    java = JAVA_HOME / "bin/java"

    # Auto-derive the signing-cert SHA-256 from the keystore if not supplied.
    if not args.cert_sha256:
        kt = subprocess.run(
            [str(JAVA_HOME / "bin" / "keytool"), "-list", "-v", "-keystore", args.keystore,
             "-storepass", args.storepass, "-alias", args.alias],
            capture_output=True, text=True)
        m = re.search(r"SHA256:\s*([0-9A-Fa-f:]+)", kt.stdout)
        if not m:
            raise SystemExit("could not read SHA-256 from keystore; pass --cert-sha256 explicitly")
        args.cert_sha256 = m.group(1).replace(":", "").lower()
        print(f"derived cert-sha256 from keystore: {args.cert_sha256}")
    args.cert_sha256 = args.cert_sha256.replace(":", "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", args.cert_sha256):
        raise SystemExit("--cert-sha256 must contain exactly 32 hexadecimal bytes")

    W = pathlib.Path(args.work)
    if W.exists():
        shutil.rmtree(W)
    W.mkdir(parents=True)
    enc_dir = W / "encrypted"
    (W / "payload").mkdir()

    # ---- 1. read input APK: dex list, abis, extract dex + bundle ----
    with zipfile.ZipFile(args.apk) as z:
        names = z.namelist()
        dex_names = sorted([n for n in names if re.fullmatch(r"classes\d*\.dex", n)], key=dexkey)
        abis = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and n.endswith(".so")})
        assert dex_names, "no classes.dex in input"
        assert "assets/index.android.bundle" in names, "no Hermes bundle in input"
        pay = W / "payload"
        for i, dn in enumerate(dex_names):
            (pay / f"dex_{i}.dex").write_bytes(z.read(dn))
        (pay / "bundle.bin.plain").write_bytes(z.read("assets/index.android.bundle"))
    if not abis:
        raise SystemExit("input APK has no native ABI; libshieldkey.so cannot be packaged")
    unsupported_abis = [abi for abi in abis if abi not in ABI_TRIPLE]
    if unsupported_abis:
        raise SystemExit(f"unsupported native ABI(s): {', '.join(unsupported_abis)}")
    print(f"input: {len(dex_names)} dex, abis={abis}")

    # ---- 2. per-build rootSecret + native secret header ----
    root_hex = secrets.token_bytes(32).hex()
    inc = W / "include"
    inc.mkdir()
    run("python3", ROOT / "tools/gen_native_secret.py",
        "--out", inc / "shield_secret.h",
        "--label", args.label, "--shares", args.shares,
        "--root-hex", root_hex, "--cert-sha256-hex", args.cert_sha256)

    # ---- RASP policy header (the native key gate reads this) ----
    rasp = rasp_config_from_env()
    (inc / "rasp_config.h").write_text(
        "/* AUTO-GENERATED per build by pack_app.py. Do not edit or commit. */\n"
        "#ifndef RASP_CONFIG_H\n#define RASP_CONFIG_H\n"
        f"#define RASP_ACT_FRIDA {rasp['frida']}\n"
        f"#define RASP_ACT_DEBUG {rasp['debug']}\n"
        f"#define RASP_ACT_ROOT {rasp['root']}\n"
        f"#define RASP_ACT_EMULATOR {rasp['emulator']}\n"
        f"#define RASP_CRYPTO_GATE {1 if (rasp['enabled'] and rasp['crypto_gate']) else 0}\n"
        "#endif\n")
    print(f"rasp: enabled={rasp['enabled']} frida={rasp['frida']} debug={rasp['debug']} "
          f"root={rasp['root']} emulator={rasp['emulator']} periodic={rasp['periodic']} "
          f"period_ms={rasp['period_ms']} crypto_gate={rasp['crypto_gate']}")

    # ---- 3. encrypt DEX + bundle with the Java Envelope (format-identical to runtime) ----
    tool_cls = W / "toolcls"
    run(javac, "-d", tool_cls,
        ROOT / "runtime/lab/shield/Envelope.java",
        ROOT / "core/lab/shield/KeyBinding.java",
        ROOT / "tools/EncryptTool.java")
    pairs = []
    for i in range(len(dex_names)):
        pairs += [f"dex/{i}", str(pay / f"dex_{i}.dex")]
    pairs += ["bundle", str(pay / "bundle.bin.plain")]
    run(java, "-cp", tool_cls, "EncryptTool", root_hex, args.cert_sha256, args.label, enc_dir, *pairs)

    # ---- 4. bootstrap classes.dex (plaintext BootFactory + runtime) ----
    gen = W / "gen/lab/shield"
    gen.mkdir(parents=True)
    (gen / "BuildSecrets.java").write_text(
        "package lab.shield; public final class BuildSecrets {"
        f' public static final int DEX_COUNT={len(dex_names)};'
        f' public static final String ORIGINAL_FACTORY="{args.original_factory}"; }}')
    (gen / "RaspConfig.java").write_text(
        "package lab.shield; public final class RaspConfig { private RaspConfig() {}"
        f" public static final boolean ENABLED={'true' if rasp['enabled'] else 'false'};"
        f" public static final int FRIDA={rasp['frida']}, DEBUG={rasp['debug']},"
        f" ROOT={rasp['root']}, EMULATOR={rasp['emulator']};"
        f" public static final boolean PERIODIC={'true' if rasp['periodic'] else 'false'};"
        f" public static final int PERIOD_MS={rasp['period_ms']}; }}")
    boot_cls = W / "bootcls"
    runtime_srcs = list((ROOT / "runtime/lab/shield").glob("*.java"))
    run(javac, "-classpath", ANDROID_JAR, "-d", boot_cls, *runtime_srcs,
        gen / "BuildSecrets.java", gen / "RaspConfig.java")
    boot_dex = W / "bootdex"
    boot_dex.mkdir()
    classfiles = [p for p in boot_cls.rglob("*.class")]
    run(BT / exe("d8"), "--min-api", args.min_sdk, "--lib", ANDROID_JAR,
        "--output", boot_dex, *classfiles)

    # ---- 5. libshieldkey.so per ABI ----
    libs = W / "libs"
    for abi in abis:
        triple = ABI_TRIPLE.get(abi)
        if not triple:
            print(f"  skip unknown abi {abi}")
            continue
        clang = tc / (f"{triple}{args.min_sdk}-clang" + (".cmd" if platform.system() == "Windows" else ""))
        outso = libs / abi / "libshieldkey.so"
        outso.parent.mkdir(parents=True, exist_ok=True)
        run(clang, "-shared", "-fPIC", "-O2", "-fvisibility=hidden", "-s",
            "-Wl,-z,max-page-size=16384",   # 16 KB-page aligned (Android 15+/16k devices)
            "-I", ROOT / "native/shieldkey", "-I", ROOT / "native/rasp", "-I", inc,
            ROOT / "native/shieldkey/shieldcrypto.c",
            ROOT / "native/shieldkey/shieldkey.c",
            ROOT / "native/shieldkey/shieldkey_jni.c",
            ROOT / "native/rasp/rasp.c",
            ROOT / "native/rasp/rasp_jni.c",
            "-o", outso)
    print(f"built libshieldkey.so for {abis}")

    # ---- 6. assemble the protected (unsigned) APK ----
    unaligned = W / "unaligned.apk"
    drop_dex = set(dex_names)
    with zipfile.ZipFile(args.apk) as zin, zipfile.ZipFile(unaligned, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            n = item.filename
            if n in drop_dex:                       continue   # encrypted
            if n == "assets/index.android.bundle":  continue   # encrypted
            if n.startswith("META-INF/") and n.split("/")[-1].rsplit(".", 1)[-1] in ("RSA", "SF", "MF"):
                continue                                        # old signature
            zout.writestr(item, zin.read(n))
        # bootstrap dex as classes.dex
        zout.writestr("classes.dex", (boot_dex / "classes.dex").read_bytes())
        # encrypted payloads
        for binf in sorted(enc_dir.rglob("*.bin")):
            rel = binf.relative_to(enc_dir).as_posix()
            zout.writestr(f"assets/shield/{rel}", binf.read_bytes())
        # Native key library: uncompressed so Android can mmap it from the APK.
        for so in sorted(libs.rglob("libshieldkey.so")):
            abi = so.parent.name
            zi = zipfile.ZipInfo(f"lib/{abi}/libshieldkey.so")
            zi.compress_type = zipfile.ZIP_STORED
            zout.writestr(zi, so.read_bytes())

    # ---- 7. align + sign ----
    aligned = W / "unsigned.apk"
    # zipalign is a native executable on Windows; d8 and apksigner are scripts.
    zipalign = "zipalign.exe" if platform.system() == "Windows" else "zipalign"
    # -P 16 aligns uncompressed .so entries to 16 KiB; the trailing 4 aligns
    # other applicable uncompressed entries to four bytes.
    run(BT / zipalign, "-f", "-P", "16", "4", unaligned, aligned)
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    run(BT / exe("apksigner"), "sign", "--ks", args.keystore, "--ks-key-alias", args.alias,
        "--ks-pass", f"pass:{args.storepass}", "--key-pass", f"pass:{args.keypass}",
        "--out", out, aligned)
    run(BT / exe("apksigner"), "verify", out)
    print(f"\nPROTECTED APK: {out}")

if __name__ == "__main__":
    main()
