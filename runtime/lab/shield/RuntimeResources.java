package lab.shield;

/**
 * Decrypts protected payloads (DEX and the Hermes bundle) with a key derived at runtime
 * and bound to the signing certificate:
 *   certHash = ApkCert.signerSha256(apk);  key = NativeKey.derive(certHash)
 * No key is stored in the app; the raw rootSecret lives only inside libshieldkey.so, and
 * NativeKey returns null (so decryption fails) unless the running APK's signer matches.
 *
 * Scope: DEX + Hermes bundle. Resources stay plaintext, so there is no resource-loader path.
 */
public final class RuntimeResources {
    private RuntimeResources() {}

    public static byte[] decryptEntry(String apk, String identity) throws Exception {
        try (java.util.zip.ZipFile zip = new java.util.zip.ZipFile(apk)) {
            java.util.zip.ZipEntry entry = zip.getEntry("assets/shield/" + identity + ".bin");
            if (entry == null) throw new SecurityException("missing payload: " + identity);
            try (java.io.InputStream in = zip.getInputStream(entry)) {
                return decryptStream(apk, in, identity);
            }
        }
    }

    private static byte[] decryptStream(String apk, java.io.InputStream in, String identity) throws Exception {
        byte[] certHash = ApkCert.signerSha256(apk);
        byte[] key = NativeKey.derive(certHash);
        java.util.Arrays.fill(certHash, (byte) 0);
        if (key == null) throw new SecurityException("signature mismatch; content key unavailable");
        try (java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream()) {
            byte[] buffer = new byte[32768];
            int n;
            while ((n = in.read(buffer)) != -1) {
                if ((long) out.size() + n > 128L * 1024 * 1024 + 32) throw new SecurityException("payload limit");
                out.write(buffer, 0, n);
            }
            return Envelope.decrypt(out.toByteArray(), key, identity);
        } finally {
            java.util.Arrays.fill(key, (byte) 0);
        }
    }
}
