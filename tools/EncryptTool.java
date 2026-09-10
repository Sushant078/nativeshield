import lab.shield.Envelope;
import lab.shield.KeyBinding;
import java.nio.file.*;

/**
 * Packer-side encryption. Derives the content key exactly as the device will
 * (key = HKDF(rootSecret, certSha256, "NSL:<label>")) and seals each payload with the
 * shared Envelope so the runtime decrypts byte-for-byte.
 *
 * Args: <rootHex> <certHex> <label> <outDir> then repeating <identity> <inFile> pairs.
 */
public final class EncryptTool {
    public static void main(String[] a) throws Exception {
        byte[] root = hex(a[0]);
        byte[] cert = hex(a[1]);
        String label = a[2];
        Path outDir = Paths.get(a[3]);
        byte[] key = KeyBinding.deriveContentKey(root, cert, label);
        int count = 0;
        for (int i = 4; i + 1 < a.length; i += 2) {
            String identity = a[i];
            byte[] plain = Files.readAllBytes(Paths.get(a[i + 1]));
            byte[] sealed = Envelope.encrypt(plain, key, identity);
            Path dest = outDir.resolve(identity + ".bin");
            Files.createDirectories(dest.getParent());
            Files.write(dest, sealed);
            java.util.Arrays.fill(plain, (byte) 0);
            count++;
        }
        java.util.Arrays.fill(key, (byte) 0);
        System.out.println("encrypted " + count + " payloads");
    }

    static byte[] hex(String s) {
        byte[] o = new byte[s.length() / 2];
        for (int i = 0; i < o.length; i++) o[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return o;
    }
}
