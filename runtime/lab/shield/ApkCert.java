package lab.shield;

import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;

/**
 * Extracts the SHA-256 of the running APK's signing certificate directly from the
 * APK Signing Block (v3 preferred, falls back to v2). Needs only the APK file path,
 * so it works in BootFactory.instantiateClassLoader before any Context exists.
 *
 * This is the "live" signer hash used as the HKDF salt and checked by the native gate:
 * if an attacker re-signs the APK, this value changes and the derived key no longer matches.
 */
public final class ApkCert {
    private ApkCert() {}

    private static final int V2_ID = 0x7109871a;
    private static final int V3_ID = 0xf05368c0;
    private static final long SIG_BLOCK_MAGIC_LO = 0x20676953204b5041L; // "APK Sig " (LE)
    private static final long SIG_BLOCK_MAGIC_HI = 0x3234206b636f6c42L; // "Block 42" (LE)

    /** @return 32-byte SHA-256 of the first signer certificate, or throws. */
    public static byte[] signerSha256(String apkPath) throws Exception {
        try (RandomAccessFile f = new RandomAccessFile(apkPath, "r")) {
            long fileLen = f.length();
            long cdOffset = centralDirOffset(f, fileLen);

            // Footer: [24 bytes before cdOffset] = 8-byte blockSize + 16-byte magic.
            byte[] footer = readAt(f, cdOffset - 24, 24);
            ByteBuffer fb = le(footer);
            long blockSizeFooter = fb.getLong(0);
            if (fb.getLong(8) != SIG_BLOCK_MAGIC_LO || fb.getLong(16) != SIG_BLOCK_MAGIC_HI)
                throw new SecurityException("APK Signing Block magic not found");

            long blockStart = cdOffset - blockSizeFooter - 8;
            byte[] block = readAt(f, blockStart, (int) (cdOffset - blockStart));
            ByteBuffer bb = le(block);

            // Iterate id-value pairs between leading size (offset 8) and footer (24 bytes).
            byte[] v3 = null, v2 = null;
            long pos = 8;
            long limit = block.length - 24;
            while (pos < limit) {
                long pairLen = bb.getLong((int) pos);
                int id = bb.getInt((int) (pos + 8));
                int valOff = (int) (pos + 12);
                int valLen = (int) (pairLen - 4);
                if (id == V3_ID) v3 = slice(block, valOff, valLen);
                else if (id == V2_ID) v2 = slice(block, valOff, valLen);
                pos += 8 + pairLen;
            }
            byte[] scheme = (v3 != null) ? v3 : v2;
            if (scheme == null) throw new SecurityException("no v2/v3 signature block");
            byte[] certDer = firstCert(scheme);
            return MessageDigest.getInstance("SHA-256").digest(certDer);
        }
    }

    /** signers -> signer -> signed data -> [digests][certificates -> first cert]. All u32-LE length-prefixed. */
    private static byte[] firstCert(byte[] scheme) {
        ByteBuffer b = le(scheme);
        int p = 0;
        int signersLen = b.getInt(p); p += 4;                 // length of signers sequence
        int signerLen = b.getInt(p); p += 4;                  // first signer
        int signedDataLen = b.getInt(p); p += 4;              // signed data
        int signedDataStart = p;
        int digestsLen = b.getInt(p); p += 4;                 // digests block
        p += digestsLen;                                      // skip digests
        int certsLen = b.getInt(p); p += 4;                   // certificates sequence
        int firstCertLen = b.getInt(p); p += 4;               // first certificate
        return slice(scheme, p, firstCertLen);
    }

    private static long centralDirOffset(RandomAccessFile f, long fileLen) throws Exception {
        // Scan backwards for EOCD signature 0x06054b50; read CD offset at EOCD+16.
        int maxBack = (int) Math.min(fileLen, 64 * 1024 + 22);
        byte[] tail = readAt(f, fileLen - maxBack, maxBack);
        for (int i = tail.length - 22; i >= 0; i--) {
            if ((tail[i] & 0xff) == 0x50 && (tail[i+1] & 0xff) == 0x4b
                    && (tail[i+2] & 0xff) == 0x05 && (tail[i+3] & 0xff) == 0x06) {
                ByteBuffer e = le(slice(tail, i, 22));
                return e.getInt(16) & 0xffffffffL;
            }
        }
        throw new SecurityException("EOCD not found");
    }

    private static byte[] readAt(RandomAccessFile f, long off, int len) throws Exception {
        byte[] buf = new byte[len];
        f.seek(off);
        f.readFully(buf);
        return buf;
    }
    private static byte[] slice(byte[] src, int off, int len) {
        byte[] out = new byte[len];
        System.arraycopy(src, off, out, 0, len);
        return out;
    }
    private static ByteBuffer le(byte[] b) { return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN); }
}
