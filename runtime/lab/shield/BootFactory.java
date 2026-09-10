package lab.shield;

import android.app.AppComponentFactory;
import android.app.Application;
import android.app.Activity;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import dalvik.system.InMemoryDexClassLoader;
import java.nio.ByteBuffer;
import java.util.Arrays;

/** Android creates the actual Application using this returned loader; no Application swap. */
public final class BootFactory extends AppComponentFactory {
    private AppComponentFactory delegate;
    private static ClassLoader installedLoader;
    static ClassLoader activeLoader(ClassLoader fallback) { return installedLoader == null ? fallback : installedLoader; }
    @Override public ClassLoader instantiateClassLoader(ClassLoader parent, ApplicationInfo info) {
        try {
            ByteBuffer[] dex = new ByteBuffer[BuildSecrets.DEX_COUNT];
            for (int i = 0; i < dex.length; i++) {
                byte[] plain = RuntimeResources.decryptEntry(info.sourceDir, "dex/" + i);
                dex[i] = ByteBuffer.allocateDirect(plain.length);
                dex[i].put(plain).flip();
                Arrays.fill(plain, (byte) 0);
            }
            String nativePath = info.nativeLibraryDir;
            for (String abi : android.os.Build.SUPPORTED_ABIS) {
                nativePath += java.io.File.pathSeparator + info.sourceDir + "!/lib/" + abi;
            }
            ClassLoader payload = new InMemoryDexClassLoader(dex, nativePath, parent);
            delegate = (AppComponentFactory) payload.loadClass(BuildSecrets.ORIGINAL_FACTORY)
                    .getDeclaredConstructor().newInstance();
            installedLoader = delegate.instantiateClassLoader(payload, info);
            return installedLoader;
        } catch (Exception e) {
            throw new SecurityException("encrypted DEX initialization failed", e);
        }
    }
    private AppComponentFactory original() {
        if (delegate == null) throw new IllegalStateException("component factory not initialized");
        return delegate;
    }
    @Override public Application instantiateApplication(ClassLoader cl, String name)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        return original().instantiateApplication(activeLoader(cl), name);
    }
    @Override public Activity instantiateActivity(ClassLoader cl, String name, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        return original().instantiateActivity(activeLoader(cl), name, intent);
    }
    @Override public ContentProvider instantiateProvider(ClassLoader cl, String name)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        return original().instantiateProvider(activeLoader(cl), name);
    }
    @Override public Service instantiateService(ClassLoader cl, String name, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        return original().instantiateService(activeLoader(cl), name, intent);
    }
    @Override public BroadcastReceiver instantiateReceiver(ClassLoader cl, String name, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        return original().instantiateReceiver(activeLoader(cl), name, intent);
    }
}
