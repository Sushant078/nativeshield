package lab.shield;

import android.content.Context;
import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.util.Arrays;

/**
 * Decrypts the Hermes bundle for React Native with the smallest possible on-disk footprint.
 *
 * Primary path: create a nameless inode with O_TMPFILE in codeCacheDir, write the plaintext,
 * and hand RN a /proc/self/fd path. The bundle never has a filename on disk (nothing to ls,
 * adb pull, or race), the data lives only as a short-lived nameless inode in app-private
 * FBE-encrypted storage, and its blocks are freed the moment the held fd closes. RN's native
 * loader can open() this path because a regular app_data_file inode is SELinux-openable by the
 * app (unlike a memfd, which is refused).
 *
 * Fallback: if O_TMPFILE is unsupported by the filesystem, write a named temp file and unlink
 * it a few seconds after Hermes mmap's it. Guarantees the app never fails to load its bundle.
 */
public final class BundleLoader {
    private BundleLoader() {}

    // O_TMPFILE is not exposed by OsConstants. Its value is identical across every Android ABI
    // (arm, arm64, x86, x86_64 all use the asm-generic __O_TMPFILE|O_DIRECTORY == 0x410000).
    private static final int O_TMPFILE = 0x410000;

    private static ParcelFileDescriptor heldFd;   // keeps the nameless inode alive for the process
    private static volatile File fallbackFile;

    /**
     * Returns a loadable bundle path if this APK is protected, else null so RN falls back to its
     * default bundle source (keeps dev / plain-release builds working unchanged).
     */
    public static String pathIfPresent(Context ctx) {
        String apk = ctx.getApplicationInfo().sourceDir;
        try (java.util.zip.ZipFile z = new java.util.zip.ZipFile(apk)) {
            if (z.getEntry("assets/shield/bundle.bin") == null) return null;
        } catch (Exception e) {
            return null;
        }
        return load(ctx, apk);
    }

    private static synchronized String load(Context ctx, String apk) {
        if (heldFd != null) return "/proc/self/fd/" + heldFd.getFd();
        if (fallbackFile != null && fallbackFile.exists()) return fallbackFile.getAbsolutePath();

        byte[] plain = null;
        try {
            plain = RuntimeResources.decryptEntry(apk, "bundle");
            try {
                return viaTmpfile(ctx, plain);
            } catch (ErrnoException | java.io.IOException tmpfileUnsupported) {
                return viaNamedFile(ctx, plain);
            }
        } catch (Exception e) {
            throw new SecurityException("encrypted bundle initialization failed", e);
        } finally {
            if (plain != null) Arrays.fill(plain, (byte) 0);
        }
    }

    /** Nameless O_TMPFILE inode exposed through /proc/self/fd — no filename ever exists. */
    private static String viaTmpfile(Context ctx, byte[] plain) throws ErrnoException, java.io.IOException {
        FileDescriptor fd = Os.open(ctx.getCodeCacheDir().getPath(), O_TMPFILE | OsConstants.O_RDWR, 0600);
        try {
            int off = 0;
            while (off < plain.length) {
                int n = Os.write(fd, plain, off, plain.length - off);
                if (n <= 0) throw new java.io.IOException("bundle write failed");
                off += n;
            }
            Os.lseek(fd, 0, OsConstants.SEEK_SET);
            heldFd = ParcelFileDescriptor.dup(fd);
        } finally {
            Os.close(fd);
        }
        return "/proc/self/fd/" + heldFd.getFd();
    }

    /** Fallback: named temp file, unlinked shortly after Hermes has mmap'd it. */
    private static String viaNamedFile(Context ctx, byte[] plain) throws java.io.IOException {
        File f = File.createTempFile("shield-", ".bundle", ctx.getCodeCacheDir());
        f.setReadable(false, false);
        f.setReadable(true, true);            // owner only
        try (FileOutputStream os = new FileOutputStream(f)) {
            os.write(plain);
            os.getFD().sync();
        }
        fallbackFile = f;
        Thread t = new Thread(() -> {
            try { Thread.sleep(15000); } catch (InterruptedException ignored) {}
            f.delete();
        });
        t.setDaemon(true);
        t.setName("shield-bundle-unlink");
        t.start();
        return f.getAbsolutePath();
    }
}
