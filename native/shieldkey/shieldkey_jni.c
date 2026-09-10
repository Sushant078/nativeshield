#include <jni.h>
#include <string.h>
#include <stdint.h>

int shield_derive_key(const uint8_t *live_cert_sha256, uint8_t out_key[32]);

/* Java: package lab.shield; class NativeKey { static native byte[] derive(byte[] certSha256); }
 * Returns the 32-byte content key, or null if the running APK's signing cert does not match. */
JNIEXPORT jbyteArray JNICALL
Java_lab_shield_NativeKey_derive(JNIEnv *env, jclass clazz, jbyteArray certSha256) {
    (void)clazz;
    if (certSha256 == NULL || (*env)->GetArrayLength(env, certSha256) != 32) return NULL;
    jbyte cert[32];
    (*env)->GetByteArrayRegion(env, certSha256, 0, 32, cert);

    uint8_t key[32];
    int rc = shield_derive_key((const uint8_t *)cert, key);
    memset(cert, 0, sizeof(cert));
    if (rc != 0) { memset(key, 0, sizeof(key)); return NULL; }

    jbyteArray out = (*env)->NewByteArray(env, 32);
    if (out != NULL) (*env)->SetByteArrayRegion(env, out, 0, 32, (const jbyte *)key);
    memset(key, 0, sizeof(key));
    return out;
}
