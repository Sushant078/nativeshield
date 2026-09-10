import lab.shield.Envelope;
import lab.shield.KeyBinding;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Offline proof of the signature-binding property. No Android required.
 *
 * Simulates the whole point of the design:
 *   1. Pack time: encrypt a payload with a key derived from OUR cert (zersys_alias stand-in).
 *   2. Runtime, genuine app: same cert -> same key -> decrypts. PASS.
 *   3. Runtime, attacker re-signed the APK: different cert -> different key -> GCM auth FAILS.
 *   4. Attacker who keeps our cert but flips one ciphertext byte -> GCM auth FAILS.
 */
public final class DeriveTest {
    public static void main(String[] args) throws Exception {
        SecureRandom rng = new SecureRandom();

        // Per-build root secret (in production: assembled in native code, never a constant).
        byte[] rootSecret = new byte[32];
        rng.nextBytes(rootSecret);

        // Two distinct signing certificates (DER bytes stand-in).
        byte[] ourCertDer = new byte[900];      rng.nextBytes(ourCertDer);
        byte[] attackerCertDer = new byte[900]; rng.nextBytes(attackerCertDer);
        byte[] ourCertHash = KeyBinding.certSha256(ourCertDer);
        byte[] attackerCertHash = KeyBinding.certSha256(attackerCertDer);

        String label = "lab.shield.nostix:v1";
        byte[] payload = "SECRET-DEX-AND-HERMES-BUNDLE-BYTES".getBytes(StandardCharsets.UTF_8);
        String identity = "dex/0";

        // ---- Pack time: derive key from OUR cert, encrypt ----
        byte[] packKey = KeyBinding.deriveContentKey(rootSecret, ourCertHash, label);
        byte[] sealed = Envelope.encrypt(payload, packKey, identity);
        Arrays.fill(packKey, (byte) 0);

        boolean genuineOk, repackageBlocked = false, tamperBlocked = false;

        // ---- Case 1: genuine app, same cert ----
        byte[] k1 = KeyBinding.deriveContentKey(rootSecret, ourCertHash, label);
        byte[] out = Envelope.decrypt(sealed, k1, identity);
        Arrays.fill(k1, (byte) 0);
        genuineOk = Arrays.equals(out, payload);

        // ---- Case 2: attacker re-signed with a different cert ----
        byte[] k2 = KeyBinding.deriveContentKey(rootSecret, attackerCertHash, label);
        try { Envelope.decrypt(sealed, k2, identity); }
        catch (javax.crypto.AEADBadTagException e) { repackageBlocked = true; }
        Arrays.fill(k2, (byte) 0);

        // ---- Case 3: same cert but tampered ciphertext ----
        byte[] k3 = KeyBinding.deriveContentKey(rootSecret, ourCertHash, label);
        byte[] tampered = sealed.clone();
        tampered[tampered.length - 1] ^= 0x01;
        try { Envelope.decrypt(tampered, k3, identity); }
        catch (javax.crypto.AEADBadTagException e) { tamperBlocked = true; }
        Arrays.fill(k3, (byte) 0);

        System.out.println("genuine cert decrypts        : " + (genuineOk ? "PASS" : "FAIL"));
        System.out.println("re-signed APK blocked        : " + (repackageBlocked ? "PASS" : "FAIL"));
        System.out.println("ciphertext tamper blocked    : " + (tamperBlocked ? "PASS" : "FAIL"));

        if (!(genuineOk && repackageBlocked && tamperBlocked)) {
            throw new AssertionError("signature-binding property NOT satisfied");
        }
        System.out.println("\nALL PASS — content key is bound to the signing certificate; repackaging breaks decryption.");
    }
}
