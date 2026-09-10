#include <jni.h>
#include <android/asset_manager_jni.h>
#include <stdlib.h>
#include <string.h>

JNIEXPORT jstring JNICALL Java_lab_payload_Checks_readNative(
        JNIEnv *env, jclass type, jobject java_assets, jstring java_name) {
    (void)type;
    AAssetManager *am = AAssetManager_fromJava(env, java_assets);
    const char *name = (*env)->GetStringUTFChars(env, java_name, NULL);
    AAsset *asset = AAssetManager_open(am, name, AASSET_MODE_STREAMING);
    (*env)->ReleaseStringUTFChars(env, java_name, name);
    if (!asset) return (*env)->NewStringUTF(env, "MISSING_NATIVE_ASSET");
    // Match RN 0.68's native bundle access through AAsset_getBuffer.
    off_t length = AAsset_getLength(asset);
    const void *data = AAsset_getBuffer(asset);
    if (!data || length < 0 || length > 4096) {
        AAsset_close(asset);
        return (*env)->NewStringUTF(env, "INVALID_NATIVE_ASSET");
    }
    char *copy = calloc((size_t)length + 1, 1);
    if (!copy) { AAsset_close(asset); return NULL; }
    memcpy(copy, data, (size_t)length);
    jstring result = (*env)->NewStringUTF(env, copy);
    free(copy);
    AAsset_close(asset);
    return result;
}
