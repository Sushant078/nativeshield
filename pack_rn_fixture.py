#!/usr/bin/env python3
"""Encrypt the synthetic RN fixture. Not a general APK packer or production integration."""
import hashlib
import json
from pathlib import Path
import re
import zipfile
import xml.etree.ElementTree as ET
import build as common

ROOT = Path(__file__).resolve().parent
B = ROOT / "build/rn"
ANDROID_NS = "http://schemas.android.com/apk/res/android"

def main():
    B.mkdir(parents=True, exist_ok=True)
    original = ROOT / "rn-fixture/app/build/outputs/apk/release/app-release-unsigned.apk"
    manifest_path = ROOT / "rn-fixture/app/build/intermediates/merged_manifests/release/AndroidManifest.xml"
    tree = ET.parse(manifest_path)
    manifest = tree.getroot()
    assert manifest.attrib['package'] == 'lab.shield.rnprobe'
    app = manifest.find('application')
    factory = app.attrib.get('{' + ANDROID_NS + '}appComponentFactory', 'android.app.AppComponentFactory')
    app.set('{' + ANDROID_NS + '}appComponentFactory', 'lab.shield.BootFactory')
    manifest.set('{' + ANDROID_NS + '}versionCode', '2')
    ET.register_namespace('android', ANDROID_NS)
    patched_manifest = B / "AndroidManifest.xml"
    tree.write(patched_manifest, encoding='utf-8', xml_declaration=True)
    inputs = B / "input-dex"
    inputs.mkdir(exist_ok=True)
    dex_paths = []
    with zipfile.ZipFile(original) as source:
        names = sorted((n for n in source.namelist() if re.fullmatch(r'classes\d*\.dex', n)),
                       key=lambda n: 1 if n == 'classes.dex' else int(n[7:-4]))
        for i, name in enumerate(names):
            dest = inputs / (str(i) + '.dex')
            dest.write_bytes(source.read(name))
            dex_paths.append(str(dest.relative_to(B)))
        with zipfile.ZipFile(B / 'payload-res.apk', 'w') as resources:
            for item in source.infolist():
                if item.filename in ('AndroidManifest.xml', 'resources.arsc') or item.filename.startswith(('res/', 'assets/')):
                    resources.writestr(item, source.read(item.filename))
    assert dex_paths
    pack_classes = B / 'pack-classes'
    pack_classes.mkdir(exist_ok=True)
    common.compile_java(pack_classes, [ROOT / 'tools/Pack.java', ROOT / 'runtime/lab/shield/Envelope.java'])
    common.run(common.JAVA / 'bin/java', '-cp', pack_classes, 'Pack', B, factory, *dex_paths)
    runtime = B / 'runtime-classes'
    runtime.mkdir(exist_ok=True)
    common.compile_java(runtime, [*ROOT.glob('runtime/**/*.java'), B / 'generated/lab/shield/BuildSecrets.java'])
    saved = common.B
    common.B = B
    common.dex('runtime-dex', runtime)
    common.B = saved
    common.run(common.BT / 'aapt2', 'link', '-I', common.ANDROID, '--manifest', patched_manifest,
               '-A', B / 'encrypted', '-o', B / 'shell.apk')
    native_hashes = {}
    with zipfile.ZipFile(B / 'shell.apk') as shell, zipfile.ZipFile(original) as source, zipfile.ZipFile(B / 'unaligned.apk', 'w') as out:
        for item in shell.infolist():
            if item.filename != 'resources.arsc':
                out.writestr(item, shell.read(item.filename))
        out.write(B / 'runtime-dex/classes.dex', 'classes.dex')
        for item in source.infolist():
            if item.filename.startswith('lib/') and item.filename.endswith('.so'):
                data = source.read(item.filename)
                out.writestr(item, data)
                native_hashes[item.filename] = hashlib.sha256(data).hexdigest()
    common.run(common.BT / 'zipalign', '-f', '-P', '16', '4', B / 'unaligned.apk', B / 'unsigned.apk')
    for source, output in ((original, B / 'baseline.apk'), (B / 'unsigned.apk', B / 'protected.apk')):
        common.run(common.BT / 'apksigner', 'sign', '--ks', ROOT / 'build/fixture-only.p12',
                   '--ks-pass', 'pass:fixture-only', '--key-pass', 'pass:fixture-only', '--out', output, source)
        common.run(common.BT / 'apksigner', 'verify', output)
    with zipfile.ZipFile(B / 'protected.apk') as apk:
        assert 'resources.arsc' not in apk.namelist()
        assert 'assets/index.android.bundle' not in apk.namelist()
        assert not any(n.startswith('res/') for n in apk.namelist())
        for name in apk.namelist():
            data = apk.read(name)
            for marker in ('NSL_RN_HERMES_724', 'NSL_RN_RESOURCE_318'):
                assert marker.encode() not in data and marker.encode('utf-16le') not in data, name
        for name, expected in native_hashes.items():
            assert hashlib.sha256(apk.read(name)).hexdigest() == expected
    report = {'result': 'PASS', 'application_dex_count': len(dex_paths), 'original_factory': factory,
              'native_libraries_unchanged': native_hashes, 'hermes_bundle_encrypted': True,
              'resource_table_encrypted': True,
              'baseline_sha256': hashlib.sha256((B / 'baseline.apk').read_bytes()).hexdigest(),
              'protected_sha256': hashlib.sha256((B / 'protected.apk').read_bytes()).hexdigest()}
    evidence = ROOT / 'evidence/rn-static.json'
    evidence.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS RN fixture: all application DEX and packaged assets/resources encrypted; native libraries unchanged')
    print(B / 'protected.apk')

if __name__ == '__main__':
    main()
