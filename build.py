#!/usr/bin/env python3
"""Build a synthetic encrypted APK entirely with installed SDK/JDK/NDK tools.

No Gradle repositories, network clients, private app inputs, or production keys.
"""
import json
import os
from pathlib import Path
import subprocess
import zipfile
import shutil
import re

ROOT = Path(__file__).resolve().parent
SDK = Path(os.environ.get("ANDROID_SDK_ROOT", str(Path.home() / "Library/Android/sdk")))
JAVA = Path(os.environ.get("NSL_JAVA_HOME") or subprocess.check_output(["/usr/libexec/java_home", "-v", "17"], text=True).strip())
BT = SDK / "build-tools/35.0.0"
ANDROID = SDK / "platforms/android-35/android.jar"
NDK = SDK / "ndk/29.0.13113456/toolchains/llvm/prebuilt/darwin-x86_64/bin"
B = ROOT / "build"
env = dict(os.environ, JAVA_HOME=str(JAVA), PATH=str(JAVA / "bin") + os.pathsep + os.environ.get("PATH", ""))

def run(*args):
    subprocess.run([str(a) for a in args], check=True, cwd=ROOT, env=env)

def mkdir(name):
    p = B / name
    p.mkdir(parents=True, exist_ok=True)
    return p

def compile_java(output, sources, classpath=()):
    run(JAVA / "bin/javac", "-source", "8", "-target", "8", "-Xlint:-options",
        "-classpath", os.pathsep.join(map(str, [ANDROID, *classpath])), "-d", output, *sources)

def jar_classes(name, classes):
    dest = B / name
    with zipfile.ZipFile(dest, "w") as z:
        for p in sorted(classes.rglob("*.class")):
            z.write(p, p.relative_to(classes).as_posix())
    return dest

def dex(name, classes):
    dest = mkdir(name)
    run(BT / "d8", "--min-api", "28", "--lib", ANDROID, "--output", dest,
        jar_classes(name + ".jar", classes))

def main():
    modules = Path(os.environ["NSL_NODE_MODULES"])
    hermes = modules / "hermes-engine"
    if json.loads((hermes / "package.json").read_text())["version"] != "0.11.0":
        raise RuntimeError("This experiment requires Hermes 0.11.0 to match RN 0.68")
    assets = mkdir("assets")
    shutil.copyfile(ROOT / "fixture/assets/private.txt", assets / "private.txt")
    run(hermes / "osx-bin/hermesc", "-O", "-emit-binary", "-out", assets / "index.android.bundle", ROOT / "fixture/hello.js")
    manifest = B / "AndroidManifest.xml"
    version = int(os.environ.get("NSL_VERSION_CODE", "1"))
    manifest.write_text((ROOT / "fixture/AndroidManifest.xml").read_text().replace('android:versionCode="1"', f'android:versionCode="{version}"'))
    mkdir("generated/lab/shield")
    rgen = mkdir("rgen")
    run(BT / "aapt2", "compile", "--dir", ROOT / "fixture/res", "-o", B / "resources.zip")
    run(BT / "aapt2", "link", "-I", ANDROID, "--manifest", manifest,
        "--java", rgen, "--custom-package", "lab.payload", "-A", assets,
        "-o", B / "payload-res.apk", B / "resources.zip")
    # This placeholder is a compile-time dependency only. Pack generates the actual random key.
    key_source = B / "generated/lab/shield/BuildSecrets.java"
    key_source.write_text('package lab.shield; public final class BuildSecrets { public static final String ORIGINAL_FACTORY="lab.payload.OriginalFactory"; public static final int DEX_COUNT=2; public static byte[] key(){return new byte[32];}}')
    runtime = mkdir("runtime-classes")
    compile_java(runtime, [*ROOT.glob("runtime/**/*.java"), key_source])
    secondary = mkdir("secondary-classes")
    compile_java(secondary, list(ROOT.glob("secondary/**/*.java")))
    dex("secondary-dex", secondary)
    payload = mkdir("payload-classes")
    compile_java(payload, [*ROOT.glob("fixture/**/*.java"), *rgen.rglob("*.java")], [runtime, secondary])
    dex("payload-dex", payload)
    pack = mkdir("pack-classes")
    compile_java(pack, [ROOT / "runtime/lab/shield/Envelope.java", ROOT / "tools/Pack.java"])
    run(JAVA / "bin/java", "-cp", pack, "Pack", B)
    compile_java(runtime, [*ROOT.glob("runtime/**/*.java"), key_source])
    dex("runtime-dex", runtime)
    native = mkdir("native/arm64-v8a") / "libassetprobe.so"
    for aar in ("hermes-release.aar", "hermes-cppruntime-release.aar"):
        with zipfile.ZipFile(hermes / "android" / aar) as archive:
            for item in archive.namelist():
                if item.startswith("jni/arm64-v8a/") and item.endswith(".so"):
                    (native.parent / Path(item).name).write_bytes(archive.read(item))
    rn_aar = modules / "react-native/android/com/facebook/react/react-native/0.68.5/react-native-0.68.5.aar"
    with zipfile.ZipFile(rn_aar) as archive:
        for dependency in ("libjsi.so", "libfbjni.so"):
            (native.parent / dependency).write_bytes(archive.read("jni/arm64-v8a/" + dependency))
        pending = list(native.parent.glob("*.so"))
        inspected = set()
        system = {"libc.so", "libm.so", "libdl.so", "liblog.so", "libandroid.so", "libz.so"}
        while pending:
            library = pending.pop()
            if library.name in inspected:
                continue
            inspected.add(library.name)
            dynamic = subprocess.check_output([str(NDK / "llvm-readelf"), "-d", str(library)], text=True)
            for dependency in re.findall(r"\(NEEDED\).*?\[(.*?)\]", dynamic):
                if dependency in system:
                    continue
                dest = native.parent / dependency
                if not dest.exists():
                    dest.write_bytes(archive.read("jni/arm64-v8a/" + dependency))
                pending.append(dest)
    # Compile against the older libc++ headers to match the unchanged Hermes runtime dependency.
    old_ndk = SDK / "ndk/21.4.7075529/toolchains/llvm/prebuilt/darwin-x86_64/bin"
    run(old_ndk / "aarch64-linux-android28-clang", "-c", "-fPIC", "-O2",
        ROOT / "native/assetprobe.c", "-o", B / "assetprobe.o")
    run(old_ndk / "aarch64-linux-android28-clang++", "-shared", "-fPIC", "-O2", "-std=c++14",
        "-Wl,-z,max-page-size=16384", "-I", hermes / "android/include", ROOT / "native/hermesprobe.cpp",
        B / "assetprobe.o", "-L", native.parent, "-lhermes", "-lc++_shared", "-landroid", "-o", native)
    run(BT / "aapt2", "link", "-I", ANDROID, "--manifest", manifest,
        "-A", B / "encrypted", "-o", B / "shell.apk")
    with zipfile.ZipFile(B / "shell.apk") as source, zipfile.ZipFile(B / "protected-unaligned.apk", "w") as z:
        for item in source.infolist():
            # aapt2 emits an empty table even when no application resources are supplied.
            if item.filename != "resources.arsc":
                z.writestr(item, source.read(item.filename))
        z.write(B / "runtime-dex/classes.dex", "classes.dex")
        for library in native.parent.glob("*.so"):
            z.write(library, "lib/arm64-v8a/" + library.name)
    run(BT / "zipalign", "-f", "-P", "16", "4", B / "protected-unaligned.apk", B / "protected-unsigned.apk")
    key = B / "fixture-only.p12"
    if not key.exists():
        run(JAVA / "bin/keytool", "-genkeypair", "-keystore", key, "-storepass", "fixture-only",
            "-keypass", "fixture-only", "-alias", "fixture", "-keyalg", "RSA", "-keysize", "2048",
            "-validity", "3650", "-dname", "CN=NativeShieldLab Synthetic Fixture", "-noprompt")
        key.chmod(0o600)
    run(BT / "apksigner", "sign", "--ks", key, "--ks-pass", "pass:fixture-only", "--key-pass",
        "pass:fixture-only", "--out", B / "protected.apk", B / "protected-unsigned.apk")
    run(BT / "apksigner", "verify", B / "protected.apk")
    markers = [b"NSL_RESOURCE_STRING_SECRET_519", b"NSL_HINDI_SECRET_402", b"NSL_DEX_SECRET_927",
               b"NSL_ASSET_SECRET_761", b"NSL_RAW_SECRET_839", b"NSL_HERMES_SECRET_603"]
    with zipfile.ZipFile(B / "protected.apk") as z:
        for name in z.namelist():
            data = z.read(name)
            for marker in markers:
                if marker in data or marker.decode().encode("utf-16le") in data:
                    raise AssertionError("plaintext marker in " + name)
        assert "resources.arsc" not in z.namelist()
        assert not any(n.startswith("res/") for n in z.namelist())
        assert b"Llab/payload/RealApp;" not in z.read("classes.dex")
        entries = z.namelist()
    evidence = ROOT / "evidence"
    evidence.mkdir(exist_ok=True)
    (evidence / "static.json").write_text(json.dumps({
        "result": "PASS", "cipher": "AES-256-GCM", "payload_dex_count": 2,
        "outer_resource_table": False, "plaintext_markers_found": False,
        "bootstrap_key_hardening": "none; recoverable local test key",
        "entries": entries,
    }, indent=2) + "\n")
    print("PASS static: payload DEX, resource table, layouts, raw and assets encrypted")
    print(B / "protected.apk")

if __name__ == "__main__":
    main()
