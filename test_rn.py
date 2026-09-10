#!/usr/bin/env python3
"""Compare synthetic RN baseline and encrypted build on an explicit emulator."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import xml.etree.ElementTree as ET
import re
import uuid

ROOT = Path(__file__).resolve().parent
SDK = Path(os.environ.get('ANDROID_SDK_ROOT', str(Path.home() / 'Library/Android/sdk')))

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--serial', required=True)
    p.add_argument('--label', required=True)
    args = p.parse_args()
    assert args.serial.startswith('emulator-'), 'Only emulator fixture tests are supported'
    out = ROOT / 'evidence' / args.label
    out.mkdir(parents=True, exist_ok=True)
    adb_base = [str(SDK / 'platform-tools/adb'), '-s', args.serial]
    def adb(*cmd):
        return subprocess.check_output([*adb_base, *cmd], text=True, timeout=40)
    try:
        page_size = adb('shell','getconf','PAGE_SIZE').strip()
    except subprocess.CalledProcessError:
        match = re.search(r'KernelPageSize:\s+(\d+) kB', adb('shell','cat','/proc/self/smaps'))
        page_size = str(int(match.group(1)) * 1024) if match else 'unknown'
    report = {'api': adb('shell','getprop','ro.build.version.sdk').strip(),
              'page_size': page_size, 'cases': []}
    def capture(mode):
        adb('shell','uiautomator','dump','/data/local/tmp/nsl-rn.xml')
        hierarchy = adb('shell','cat','/data/local/tmp/nsl-rn.xml')
        (out / (mode + '-initial-screen.xml')).write_text(hierarchy)
        (out / (mode + '-initial-screen.png')).write_bytes(subprocess.check_output(
            [*adb_base,'exec-out','screencap','-p'], timeout=20))
        compat = 'page size compatible mode' in hierarchy
        if compat:
            # Preserve evidence and acknowledge the observed OS warning; do not change
            # compatibility settings or suppress future warnings globally.
            buttons = [n for n in ET.fromstring(hierarchy).iter('node') if n.get('text') == 'OK']
            assert len(buttons) == 1
            x1,y1,x2,y2 = map(int, re.findall(r'\d+', buttons[0].get('bounds')))
            adb('shell','input','tap',str((x1+x2)//2),str((y1+y2)//2))
            adb('shell','uiautomator','dump','/data/local/tmp/nsl-rn.xml')
            hierarchy = adb('shell','cat','/data/local/tmp/nsl-rn.xml')
        assert 'Encrypted React Native 0.68.5 + Hermes: mounted' in hierarchy, hierarchy
        (out / (mode + '-screen.xml')).write_text(hierarchy)
        (out / (mode + '-screen.png')).write_bytes(subprocess.check_output(
            [*adb_base,'exec-out','screencap','-p'], timeout=20))
        report[mode + '_ui'] = {'mounted_text_visible': True, 'page_size_compat_warning': compat}
    # This package is exclusively the disposable fixture created by this project.
    subprocess.run([*adb_base, 'uninstall', 'lab.shield.rnprobe'], capture_output=True, timeout=30)
    for mode, starts in (('baseline', 1), ('protected', 5)):
        apk = ROOT / 'build/rn' / (mode + '.apk')
        assert 'Success' in adb('install','--no-streaming','-r',str(apk))
        for i in range(starts):
            adb('shell','am','force-stop','lab.shield.rnprobe')
            adb('logcat','-b','all','-c')
            token = uuid.uuid4().hex
            expected = 'PASS RN-0.68.5-Hermes-mounted-native-bridge-and-resource run=' + token
            adb('shell','am','start','-S','-W','-n','lab.shield.rnprobe/lab.rnprobe.MainActivity','--es','nsl_run',token)
            deadline = time.monotonic() + 30
            log = ''
            while time.monotonic() < deadline:
                log = adb('logcat','-d','-s','NativeShieldRN:I','AndroidRuntime:E','ReactNativeJS:I','libc:F')
                if expected in log or 'FATAL EXCEPTION' in log or 'Fatal signal' in log:
                    break
                time.sleep(.25)
            name = mode + '-' + str(i+1)
            (out / (name + '.log')).write_text(log)
            assert 'PASS early-provider-real-application-and-resource' in log, log
            assert expected in log, log
            assert 'FATAL EXCEPTION' not in log and 'Fatal signal' not in log, log
            report['cases'].append({'name': name, 'result': 'PASS', 'sha256': hashlib.sha256(apk.read_bytes()).hexdigest()})
            print('PASS ' + name, flush=True)
        capture(mode)
    (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(out / 'results.json')

if __name__ == '__main__':
    main()
