#!/usr/bin/env python3
"""Exercise only the synthetic fixture on an explicitly selected emulator."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import zipfile

ROOT = Path(__file__).resolve().parent
B = ROOT / "build"
SDK = Path(os.environ.get("ANDROID_SDK_ROOT", str(Path.home() / "Library/Android/sdk")))
ADB = SDK / "platform-tools/adb"
BT = SDK / "build-tools/35.0.0"
APP = "lab.shield.probe"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True)
    parser.add_argument("--cold-starts", type=int, default=5)
    parser.add_argument("--label", default="runtime")
    args = parser.parse_args()
    if not args.serial.startswith("emulator-"):
        raise SystemExit("This script only permits an emulator, never a physical device")
    evidence = ROOT / "evidence" / args.label
    evidence.mkdir(parents=True, exist_ok=True)

    def adb(*command):
        return subprocess.run([str(ADB), "-s", args.serial, *command], text=True,
                              capture_output=True, check=True, timeout=45).stdout

    if adb("shell", "getprop", "sys.boot_completed").strip() != "1":
        raise SystemExit("Emulator is not booted")
    try:
        page_size = adb("shell", "getconf", "PAGE_SIZE").strip()
    except subprocess.CalledProcessError:
        match = re.search(r"KernelPageSize:\s+(\d+) kB", adb("shell", "cat", "/proc/self/smaps"))
        page_size = str(int(match.group(1)) * 1024) if match else "unknown"
    results = {
        "api": adb("shell", "getprop", "ro.build.version.sdk").strip(),
        "page_size": page_size,
        "fingerprint": adb("shell", "getprop", "ro.build.fingerprint").strip(),
        "apk_sha256": hashlib.sha256((B / "protected.apk").read_bytes()).hexdigest(),
        "cases": [],
    }

    def install(path):
        adb("shell", "am", "force-stop", APP)
        out = adb("install", "--no-streaming", "-r", str(path))
        if "Success" not in out:
            raise AssertionError(out)

    def launch(label, expected_failure=None):
        adb("shell", "am", "force-stop", APP)
        adb("logcat", "-c")
        start = adb("shell", "am", "start", "-n", APP + "/lab.payload.MainActivity")
        deadline = time.monotonic() + 12
        log = ""
        while time.monotonic() < deadline:
            log = adb("logcat", "-d", "-s", "NativeShieldLab:I", "AndroidRuntime:E")
            if "PASS encrypted-layout-inflation" in log or "FATAL EXCEPTION" in log:
                break
            time.sleep(0.2)
        (evidence / (label + ".log")).write_text(start + "\n" + log)
        if expected_failure:
            assert "FATAL EXCEPTION" in log and expected_failure in log, log
            assert "PASS activity" not in log, log
        else:
            for expected in ("PASS provider-before-application-onCreate", "PASS activity",
                             "PASS encrypted-layout-inflation", "PASS retained-data"):
                assert expected in log, log
            assert "FATAL EXCEPTION" not in log, log
        launches = re.search(r"retained-data launches=(\d+)", log)
        count = int(launches.group(1)) if launches else None
        results["cases"].append({"name": label, "result": "PASS", "persistent_launch_count": count})
        print("PASS " + label, flush=True)
        return count

    install(B / "protected.apk")
    try:
        previous = None
        for i in range(args.cold_starts):
            count = launch("cold-" + str(i + 1))
            if previous is not None:
                assert count == previous + 1
            previous = count
        install(B / "protected.apk")
        count = launch("same-signature-reinstall-retains-data")
        assert count == previous + 1
        for identity, message in (("dex/0", "encrypted DEX initialization failed"),
                                  ("resources", "encrypted resource initialization failed")):
            corrupt_dir = B / ("runtime-" + args.label)
            corrupt_dir.mkdir(exist_ok=True)
            corrupt = corrupt_dir / ("corrupt-" + identity.replace("/", "-") + ".apk")
            with zipfile.ZipFile(B / "protected-unsigned.apk") as source, zipfile.ZipFile(corrupt, "w") as dest:
                for item in source.infolist():
                    data = source.read(item.filename)
                    if item.filename == "assets/shield/" + identity + ".bin":
                        data = data[:-1] + bytes([data[-1] ^ 1])
                    dest.writestr(item, data)
            subprocess.run([str(BT / "apksigner"), "sign", "--ks", str(B / "fixture-only.p12"),
                            "--ks-pass", "pass:fixture-only", "--key-pass", "pass:fixture-only", str(corrupt)],
                           check=True, capture_output=True, timeout=30)
            install(corrupt)
            launch("reject-corrupt-" + identity.replace("/", "-"), message)
    finally:
        install(B / "protected.apk")
    launch("restored-valid-build")
    (evidence / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(evidence / "results.json")

if __name__ == "__main__":
    main()
