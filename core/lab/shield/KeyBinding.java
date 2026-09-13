package lab.shield;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Derives the AES content key at runtime instead of storing it.
 *
 * key = HKDF-SHA256(ikm = rootSecret, salt = SHA-256(signing certificate), info = "NSL:<label>")
 *
 * The salt is the SHA-256 of the certificate that actually signs the running APK
 * (read live via PackageManager on device, or from the keystore at pack time).
 * Re-signing the APK with a different certificate changes the salt, so the derived
 * key changes, so AES-GCM authentication fails and nothing decrypts. This binds the
 * payloads to a single signer. It raises the cost of repackaging, but the native
 * derivation material remains recoverable by a sufficiently capable local attacker.
 *
 * rootSecret itself is NOT shipped as a Java constant in the real build; it is
 * assembled in native code from scattered fragments (Stage 2). This class only
 * performs the math and is shared, identically, by the offline packer and the runtime.
 */
public final class KeyBinding {
    private KeyBinding() {}

    /** RFC 5869 HKDF-SHA256. */
    static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int outLen) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        byte[] usedSalt = (salt == null || salt.length == 0) ? new byte[mac.getMacLength()] : salt;
        mac.init(new SecretKeySpec(usedSalt, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);                 // extract
        try {
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            byte[] okm = new byte[outLen];
            byte[] t = new byte[0];
            int pos = 0;
            for (int counter = 1; pos < outLen; counter++) {
                mac.reset();
                mac.update(t);
                mac.update(info);
                mac.update((byte) counter);
                t = mac.doFinal();
                int n = Math.min(t.length, outLen - pos);
                System.arraycopy(t, 0, okm, pos, n);
                pos += n;
            }
            return okm;
        } finally {
            Arrays.fill(prk, (byte) 0);
        }
    }

    /** SHA-256 of a DER-encoded signing certificate. */
    public static byte[] certSha256(byte[] certDer) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(certDer);
    }

    /**
     * Derive the 32-byte content key. Caller must zero the returned array after use.
     * @param rootSecret   per-build high-entropy secret (native-assembled at runtime)
     * @param signerCertSha256 SHA-256 of the signing certificate
     * @param label        domain separation, e.g. the package name + version
     */
    public static byte[] deriveContentKey(byte[] rootSecret, byte[] signerCertSha256, String label)
            throws Exception {
        if (rootSecret == null || rootSecret.length < 32) throw new IllegalArgumentException("weak root secret");
        if (signerCertSha256 == null || signerCertSha256.length != 32) throw new IllegalArgumentException("bad cert hash");
        byte[] info = ("NSL:" + label).getBytes(StandardCharsets.UTF_8);
        return hkdf(rootSecret, signerCertSha256, info, 32);
    }
}
