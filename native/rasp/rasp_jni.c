#include <jni.h>
#include "rasp.h"

/* Java: package lab.shield; class Rasp { static native int nativeScan(); } */
JNIEXPORT jint JNICALL
Java_lab_shield_Rasp_nativeScan(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return (jint) rasp_scan();
}
