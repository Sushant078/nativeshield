package lab.shield;

/**
 * Bridge to the native key module (libshieldkey.so). The raw rootSecret is assembled
 * only inside native code; Java receives at most the derived 32-byte content key, and
 * only when the running APK is signed by the expected certificate.
 */
public final class NativeKey {
    private NativeKey() {}

    static { System.loadLibrary("shieldkey"); }

    /**
     * @param signerCertSha256 SHA-256 of the running APK's signing certificate
     *        (from PackageManager). Must be 32 bytes.
     * @return derived content key (32 bytes), or null if the signer does not match.
     *         Caller must zero the returned array after use.
     */
    static native byte[] derive(byte[] signerCertSha256);
}
