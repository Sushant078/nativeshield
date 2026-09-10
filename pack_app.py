#!/usr/bin/env python3
"""Offline packer for BALNostixUI: encrypts DEX + Hermes bundle, key bound to the signing cert.

Input must be a release APK already built with the shield integration (manifest
appComponentFactory=lab.shield.BootFactory, MainApplication.getJSBundleFile ->
lab.shield.BundleLoader). Resources stay plaintext. Nothing here touches the network.
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

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--keystore", required=True)
    ap.add_argument("--alias", required=True)
    ap.add_argument("--storepass", required=True)
    ap.add_argument("--keypass", required=True)
    ap.add_argument("--cert-sha256", required=True, help="hex SHA-256 of the signer that re-signs this APK")
    ap.add_argument("--label", default="lab.shield.nostix:v1")
    ap.add_argument("--original-factory", default="androidx.core.app.CoreComponentFactory")
    ap.add_argument("--build-tools", default="35.0.0")
    ap.add_argument("--platform", default="android-32")
    ap.add_argument("--ndk", required=True)
    ap.add_argument("--min-sdk", default="30")
    ap.add_argument("--shares", default="4")
    args = ap.parse_args()

    BT = SDK / "build-tools" / args.build_tools
    ANDROID_JAR = SDK / "platforms" / args.platform / "android.jar"
    NDK = pathlib.Path(args.ndk)
    tc = NDK / "toolchains/llvm/prebuilt" / ndk_host_tag() / "bin"
    javac = JAVA_HOME / "bin/javac"
    java = JAVA_HOME / "bin/java"

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
    print(f"input: {len(dex_names)} dex, abis={abis}")

    # ---- 2. per-build rootSecret + native secret header ----
    root_hex = secrets.token_bytes(32).hex()
    inc = W / "include"
    inc.mkdir()
    run("python3", ROOT / "tools/gen_native_secret.py",
        "--out", inc / "shield_secret.h",
        "--label", args.label, "--shares", args.shares,
        "--root-hex", root_hex, "--cert-sha256-hex", args.cert_sha256)

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
    boot_cls = W / "bootcls"
    runtime_srcs = list((ROOT / "runtime/lab/shield").glob("*.java"))
    run(javac, "-classpath", ANDROID_JAR, "-d", boot_cls, *runtime_srcs, gen / "BuildSecrets.java")
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
            "-I", ROOT / "native/shieldkey", "-I", inc,
            ROOT / "native/shieldkey/shieldcrypto.c",
            ROOT / "native/shieldkey/shieldkey.c",
            ROOT / "native/shieldkey/shieldkey_jni.c",
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
        # native key lib (stored, not compressed, page-aligned handled by zipalign -p)
        for so in sorted(libs.rglob("libshieldkey.so")):
            abi = so.parent.name
            zi = zipfile.ZipInfo(f"lib/{abi}/libshieldkey.so")
            zi.compress_type = zipfile.ZIP_STORED
            zout.writestr(zi, so.read_bytes())

    # ---- 7. align + sign ----
    aligned = W / "unsigned.apk"
    run(BT / exe("zipalign"), "-f", "-p", "4", unaligned, aligned)
    out = pathlib.Path(args.out)
    run(BT / exe("apksigner"), "sign", "--ks", args.keystore, "--ks-key-alias", args.alias,
        "--ks-pass", f"pass:{args.storepass}", "--key-pass", f"pass:{args.keypass}",
        "--out", out, aligned)
    run(BT / exe("apksigner"), "verify", out)
    print(f"\nPROTECTED APK: {out}")

if __name__ == "__main__":
    main()
