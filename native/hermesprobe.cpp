#include <jni.h>
#include <android/asset_manager_jni.h>
#include <hermes/hermes.h>
#include <jsi/jsi.h>
#include <memory>
#include <stdexcept>

// This fixture uses the C++ Hermes API, not its separate Java executor bindings.
// An explicit entry point prevents dlsym from selecting a dependency's JNI_OnLoad.
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM*, void*) { return JNI_VERSION_1_6; }

// Exercise the actual Hermes 0.11 runtime with RN 0.68's AAsset-backed buffer pattern.
class AssetBuffer final : public facebook::jsi::Buffer {
    AAsset* asset_;
public:
    explicit AssetBuffer(AAsset* asset) : asset_(asset) {}
    ~AssetBuffer() override { AAsset_close(asset_); }
    size_t size() const override { return AAsset_getLength(asset_); }
    const uint8_t* data() const override {
        return static_cast<const uint8_t*>(AAsset_getBuffer(asset_));
    }
};

extern "C" JNIEXPORT jdouble JNICALL Java_lab_payload_Checks_evaluateHermes(
        JNIEnv* env, jclass, jobject assets) {
    try {
        auto manager = AAssetManager_fromJava(env, assets);
        AAsset* asset = AAssetManager_open(manager, "index.android.bundle", AASSET_MODE_STREAMING);
        if (!asset) throw std::runtime_error("encrypted Hermes bundle unavailable");
        auto buffer = std::make_shared<AssetBuffer>(asset);
        if (!buffer->data()) throw std::runtime_error("Hermes asset buffer unavailable");
        auto runtime = facebook::hermes::makeHermesRuntime();
        auto result = runtime->evaluateJavaScript(buffer, "assets://index.android.bundle");
        return result.asNumber();
    } catch (const std::exception& e) {
        env->ThrowNew(env->FindClass("java/lang/IllegalStateException"), e.what());
        return -1;
    }
}
