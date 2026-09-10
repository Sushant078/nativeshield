import lab.shield.KeyBinding;

/** Prints HKDF(rootSecret, certSha256, "NSL:<label>") — the exact derivation the packer uses.
 *  Args: <rootHex> <certHex> <label>. Ground truth for the native-vs-Java interop check. */
public final class DeriveRef {
    public static void main(String[] a) throws Exception {
        byte[] root = hex(a[0]);
        byte[] cert = hex(a[1]);
        byte[] key = KeyBinding.deriveContentKey(root, cert, a[2]);
        StringBuilder sb = new StringBuilder();
        for (byte b : key) sb.append(String.format("%02x", b));
        System.out.println(sb);
    }
    static byte[] hex(String s) {
        byte[] o = new byte[s.length() / 2];
        for (int i = 0; i < o.length; i++) o[i] = (byte) Integer.parseInt(s.substring(2*i, 2*i+2), 16);
        return o;
    }
}
