# SafetyDetect 6.4.0+302 dispatches this method via getDeclaredMethod(call.method).
# Preserve only this reflection target; do not disable R8 or keep all HMS code.
-keepclassmembers class com.huawei.hms.flutter.safetydetect.MethodHandler {
    private void sysIntegrity(io.flutter.plugin.common.MethodChannel$Result, io.flutter.plugin.common.MethodCall);
}
