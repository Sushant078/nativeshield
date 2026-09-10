package lab.shield;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Versioned authenticated envelope shared by the offline packer and Android runtime. */
public final class Envelope {
    private static final byte[] MAGIC = {'N', 'S', 'L', '1'};
    private static final int MAX = 128 * 1024 * 1024;
    private static byte[] aad(String identity) {
        return ("NativeShieldLab:v1:" + identity).getBytes(StandardCharsets.UTF_8);
    }
    public static byte[] encrypt(byte[] plain, byte[] key, String identity) throws Exception {
        if (plain.length > MAX) throw new IllegalArgumentException("payload too large");
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        c.updateAAD(aad(identity));
        byte[] encrypted = c.doFinal(plain);
        byte[] out = new byte[16 + encrypted.length];
        System.arraycopy(MAGIC, 0, out, 0, 4);
        System.arraycopy(nonce, 0, out, 4, 12);
        System.arraycopy(encrypted, 0, out, 16, encrypted.length);
        return out;
    }
    public static byte[] decrypt(byte[] encoded, byte[] key, String identity) throws Exception {
        if (encoded.length < 32 || encoded.length > MAX + 32 ||
                !Arrays.equals(MAGIC, Arrays.copyOf(encoded, 4))) {
            throw new SecurityException("invalid envelope");
        }
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, Arrays.copyOfRange(encoded, 4, 16)));
        c.updateAAD(aad(identity));
        return c.doFinal(encoded, 16, encoded.length - 16);
    }
}
