package lab.shield;

import android.content.Context;
import android.os.Build;
import android.os.Debug;
import android.os.Process;
import android.util.Log;

/**
 * Runtime application self-protection: root / Frida / debugger / emulator detection
 * with per-category policy (off / report / enforce) baked in at pack time via
 * {@link RaspConfig}. Two evaluation modes, both wired here:
 *
 *   - op-bound  : the native key gate (shield_derive_key -> rasp_block_key) refuses
 *                 decryption to a Frida/debugger-tampered process, plus {@link #checkNow}
 *                 for an app to call before a sensitive operation.
 *   - periodic  : a low-frequency background thread re-scans while the app is alive.
 *
 * On an *enforced* detection the registered app callback (a Runnable) is invoked so the
 * app decides what to do; if none is registered the process is terminated. Reported-only
 * detections are logged and never block, so QA can run on rooted / emulator devices.
 */
public final class Rasp {
    private Rasp() {}

    private static final String TAG = "shield.rasp";

    /* detection flags — must match native rasp.h */
    public static final int FRIDA    = 0x01;
    public static final int DEBUGGER = 0x02;
    public static final int ROOT     = 0x04;
    public static final int EMULATOR = 0x08;

    /* action values — must match RaspConfig */
    private static final int OFF = 0, REPORT = 1, ENFORCE = 2;

    static {
        try { System.loadLibrary("shieldkey"); } catch (Throwable ignored) {}
    }

    private static native int nativeScan();

    private static volatile Runnable callback;
    private static volatile Thread worker;
    private static volatile int lastThreat;

    /** Flags from the most recent enforced detection (for a callback to inspect). */
    public static int lastThreat() { return lastThreat; }

    /**
     * Run every enabled probe once and return the OR of detected flags. Also applies
     * policy (logs reported categories, fires the enforce path for enforced ones).
     * An app may call this before a sensitive operation for an extra op-bound check.
     */
    public static int checkNow() {
        if (!RaspConfig.ENABLED) return 0;
        int detected = scan();
        handle(detected);
        return detected;
    }

    /**
     * Register the app callback and, if configured, start the periodic scanner.
     * Safe to call from Application.onCreate. Reflection-friendly signature
     * (Context + Runnable) so the app has no compile-time dependency on this class.
     */
    public static synchronized void start(Context ctx, Runnable onEnforcedThreat) {
        if (!RaspConfig.ENABLED) return;
        callback = onEnforcedThreat;
        checkNow();
        if (RaspConfig.PERIODIC && worker == null) {
            worker = new Thread(new Runnable() {
                @Override public void run() {
                    int period = RaspConfig.PERIOD_MS > 0 ? RaspConfig.PERIOD_MS : 3000;
                    for (;;) {
                        try { Thread.sleep(period); } catch (InterruptedException e) { return; }
                        try { handle(scan()); } catch (Throwable ignored) {}
                    }
                }
            }, "shield-rasp");
            worker.setDaemon(true);
            worker.start();
        }
    }

    private static int scan() {
        int f = 0;
        try { f |= nativeScan(); } catch (Throwable ignored) {}
        // Java-side signals that complement the native probes.
        try {
            String tags = Build.TAGS;
            if (tags != null && tags.contains("test-keys")) f |= ROOT;
        } catch (Throwable ignored) {}
        try {
            if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) f |= DEBUGGER;
        } catch (Throwable ignored) {}
        return f;
    }

    private static int actionFor(int flag) {
        switch (flag) {
            case FRIDA:    return RaspConfig.FRIDA;
            case DEBUGGER: return RaspConfig.DEBUG;
            case ROOT:     return RaspConfig.ROOT;
            case EMULATOR: return RaspConfig.EMULATOR;
            default:       return OFF;
        }
    }

    private static void handle(int detected) {
        if (detected == 0) return;
        int enforced = 0;
        int[] all = { FRIDA, DEBUGGER, ROOT, EMULATOR };
        for (int flag : all) {
            if ((detected & flag) == 0) continue;
            int act = actionFor(flag);
            if (act == REPORT)  Log.w(TAG, "detected (report): " + name(flag));
            if (act == ENFORCE) { Log.e(TAG, "detected (enforce): " + name(flag)); enforced |= flag; }
        }
        if (enforced == 0) return;
        lastThreat = enforced;
        Runnable cb = callback;
        if (cb != null) {
            try { cb.run(); return; } catch (Throwable ignored) {}
        }
        // No app callback (or it threw): fail closed.
        Process.killProcess(Process.myPid());
        System.exit(1);
    }

    private static String name(int flag) {
        switch (flag) {
            case FRIDA:    return "frida";
            case DEBUGGER: return "debugger";
            case ROOT:     return "root";
            case EMULATOR: return "emulator";
            default:       return "unknown";
        }
    }
}
