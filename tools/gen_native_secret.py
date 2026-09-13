#!/usr/bin/env python3
"""Generate the per-build native secret header (shield_secret.h).

The rootSecret is split into N random XOR shares so no single array in the .so
holds it. The expected signing-cert SHA-256 is baked in as the runtime gate.

    A real packer run passes the application signing-cert hash and a fresh
random rootSecret, and will NOT emit the sidecar files. --test-artifacts writes the
rootSecret and cert hash out so the offline unit test can cross-check the native
derivation against the Java packer derivation.
"""
import argparse, secrets, hashlib, hmac, pathlib, re

def hkdf_sha256(ikm, salt, info, length=32):
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, counter = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t; counter += 1
    return okm[:length]

def c_array(name, data):
    body = ",".join(str(b) for b in data)
    return f"static const unsigned char {name}[{len(data)}] = {{{body}}};\n"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="path to shield_secret.h")
    ap.add_argument("--label", default="dev.nativeshield:v1")
    ap.add_argument("--shares", type=int, default=3)
    ap.add_argument("--root-hex", help="32-byte rootSecret hex (default: random)")
    ap.add_argument("--cert-sha256-hex", help="32-byte signing-cert SHA-256 hex (default: random test value)")
    ap.add_argument("--test-artifacts", help="dir to write root.hex/cert.hex/expected.hex for the unit test")
    args = ap.parse_args()

    if not 2 <= args.shares <= 32:
        raise SystemExit("--shares must be between 2 and 32")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", args.label):
        raise SystemExit("--label must be 1-128 ASCII letters, digits, dot, underscore, colon, or hyphen")

    root = bytes.fromhex(args.root_hex) if args.root_hex else secrets.token_bytes(32)
    cert = bytes.fromhex(args.cert_sha256_hex) if args.cert_sha256_hex else secrets.token_bytes(32)
    assert len(root) == 32 and len(cert) == 32
    n = args.shares

    # N-1 random shares; the last share makes XOR of all shares == root.
    shares = [secrets.token_bytes(32) for _ in range(n - 1)]
    acc = bytearray(root)
    for sh in shares:
        for i in range(32):
            acc[i] ^= sh[i]
    shares.append(bytes(acc))

    info = ("NSL:" + args.label).encode()

    h = ["/* AUTO-GENERATED per build by gen_native_secret.py. Do not edit or commit. */\n",
         "#ifndef SHIELD_SECRET_H\n#define SHIELD_SECRET_H\n\n",
         f"#define SHIELD_SHARE_COUNT {n}\n",
         f'#define SHIELD_INFO "NSL:{args.label}"\n\n']
    for i, sh in enumerate(shares):
        h.append(c_array(f"SHIELD_SHARE_{i}", sh))
    h.append("\nstatic const unsigned char *const SHIELD_SHARES[SHIELD_SHARE_COUNT] = {")
    h.append(",".join(f"SHIELD_SHARE_{i}" for i in range(n)))
    h.append("};\n\n")
    h.append(c_array("SHIELD_CERT_SHA256", cert))
    h.append("\n#endif\n")

    out = pathlib.Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(h))

    if args.test_artifacts:
        d = pathlib.Path(args.test_artifacts); d.mkdir(parents=True, exist_ok=True)
        (d / "root.hex").write_text(root.hex())
        (d / "cert.hex").write_text(cert.hex())
        (d / "label.txt").write_text(args.label)
        (d / "expected.hex").write_text(hkdf_sha256(root, cert, info).hex())
    print(f"wrote {out} ({n} shares, label={args.label})")

if __name__ == "__main__":
    main()
