package com.mekfeya.appcheckbridge;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.TaskCompletionSource;
import com.google.android.gms.tasks.Tasks;
import com.google.firebase.FirebaseApp;
import com.google.firebase.appcheck.AppCheckProvider;
import com.google.firebase.appcheck.AppCheckToken;
import com.google.firebase.appcheck.FirebaseAppCheck;
import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Map;

/**
 * Installs only on explicit call, never on plugin registration.
 * The Firebase SDK owns caching/refresh. No tokens are written by this plugin.
 * No debug bypass, GMS error fallback, financial lease or authentication issued here.
 */
public final class MekfeyaAppCheckBridgePlugin
        implements FlutterPlugin, MethodChannel.MethodCallHandler {
    private final Handler main = new Handler(Looper.getMainLooper());
    private MethodChannel channel;
    private Context context;
    private NativeProvider provider;

    @Override public void onAttachedToEngine(FlutterPluginBinding binding) {
        context = binding.getApplicationContext();
        channel = new MethodChannel(binding.getBinaryMessenger(),
                "com.mekfeya/app_check_bridge");
        channel.setMethodCallHandler(this);
    }

    @Override public void onDetachedFromEngine(FlutterPluginBinding binding) {
        if (provider != null) provider.close();
        if (channel != null) channel.setMethodCallHandler(null);
        channel = null;
        context = null;
        provider = null;
    }

    @Override public void onMethodCall(MethodCall call, MethodChannel.Result result) {
        String failureCode = "HMS_FIREBASE_INIT";
        try {
            if (!"capability".equals(call.method) && !"installDev".equals(call.method)) {
                result.notImplemented();
                return;
            }
            FirebaseApp app = FirebaseApp.getInstance();
            failureCode = "HMS_IDENTITY_READ";
            requireIdentity(app);
            failureCode = "HMS_GMS_CHECK";
            int gms = GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(context);
            boolean mayAttemptHuawei = BridgePolicy.mayAttemptHuawei(gms);
            if ("capability".equals(call.method)) {
                // Provider selection only, never a device-integrity verdict.
                if (gms == ConnectionResult.SUCCESS) result.success("google");
                else if (gms == ConnectionResult.SERVICE_MISSING) result.success("missingGoogle");
                else if (mayAttemptHuawei) result.success("huaweiRequired");
                else result.error(BridgePolicy.gmsFailure(gms), null, null);
                return;
            }
            if (!mayAttemptHuawei) {
                result.error("HMS_PROVIDER_NOT_APPLICABLE", null, null);
                return;
            }
            failureCode = "HMS_METADATA_READ";
            ApplicationInfo host = context.getPackageManager().getApplicationInfo(
                context.getPackageName(), PackageManager.GET_META_DATA);
            if (host.metaData == null || !"appid=119433157".equals(
                    host.metaData.getString("com.huawei.hms.client.appid"))) {
                result.error("HMS_HOST_APP_ID_REQUIRED", null, null);
                return;
            }
            if (provider == null) {
                failureCode = "HMS_FACTORY_INSTALL";
                NativeProvider candidate = new NativeProvider(channel);
                FirebaseAppCheck.getInstance(app).installAppCheckProviderFactory(requested -> {
                    if (!BridgePolicy.APP.equals(requested.getOptions().getApplicationId()) ||
                            !BridgePolicy.PROJECT.equals(requested.getOptions().getProjectId())) {
                        throw new IllegalStateException("HMS_ENVIRONMENT_DENIED");
                    }
                    return candidate;
                });
                provider = candidate;
            }
            result.success(null);
        } catch (IdentityFailure denied) {
            result.error(denied.code, null, null);
        } catch (Exception ignored) {
            // Never forward SDK exception text, tokens or credential details.
            result.error(failureCode, null, null);
        }
    }

    private static final class IdentityFailure extends Exception {
        final String code;
        IdentityFailure(String code) { this.code = code; }
    }

    @SuppressWarnings("deprecation")
    private void requireIdentity(FirebaseApp app) throws Exception {
        PackageManager pm = context.getPackageManager();
        PackageInfo info = pm.getPackageInfo(context.getPackageName(),
            Build.VERSION.SDK_INT >= 28 ? PackageManager.GET_SIGNING_CERTIFICATES :
                PackageManager.GET_SIGNATURES);
        Signature[] signatures = Build.VERSION.SDK_INT >= 28
            ? info.signingInfo.getApkContentsSigners() : info.signatures;
        String[] hashes = new String[signatures.length];
        for (int i = 0; i < signatures.length; i++) {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(signatures[i].toByteArray());
            StringBuilder hex = new StringBuilder();
            for (byte b : digest) hex.append(String.format(Locale.ROOT, "%02x", b & 255));
            hashes[i] = hex.toString();
        }
        boolean debug = (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        if (!BridgePolicy.allowed(app.getOptions().getProjectId(),
                app.getOptions().getApplicationId(), context.getPackageName(), debug, hashes)) {
            throw new IdentityFailure(BridgePolicy.identityFailure(
                app.getOptions().getProjectId(), app.getOptions().getApplicationId(),
                context.getPackageName(), debug, hashes));
        }
    }

    private final class NativeProvider implements AppCheckProvider {
        private final MethodChannel callback;
        private TaskCompletionSource<AppCheckToken> pending;
        private boolean closed;
        NativeProvider(MethodChannel callback) { this.callback = callback; }

        @Override public synchronized Task<AppCheckToken> getToken() {
            if (closed) return Tasks.forException(new Exception("HMS_BRIDGE_UNAVAILABLE"));
            if (pending != null) return pending.getTask();
            TaskCompletionSource<AppCheckToken> request = new TaskCompletionSource<>();
            pending = request;
            main.post(() -> {
                synchronized (NativeProvider.this) {
                    if (closed || pending != request) return;
                }
                Runnable timeout = () -> finish(request, null);
                main.postDelayed(timeout, 25000);
                callback.invokeMethod("getToken", null, new MethodChannel.Result() {
                    @Override public void success(Object data) {
                        main.removeCallbacks(timeout);
                        AppCheckToken token = null;
                        if (data instanceof Map) {
                            Object text = ((Map<?, ?>) data).get("token");
                            Object expiry = ((Map<?, ?>) data).get("expiresAtMillis");
                            if (text instanceof String && expiry instanceof Number) {
                                String value = (String) text;
                                long end = ((Number) expiry).longValue();
                                if (BridgePolicy.validTokenShape(value, end, System.currentTimeMillis())) {
                                    token = new AppCheckToken() {
                                        @Override public String getToken() { return value; }
                                        @Override public long getExpireTimeMillis() { return end; }
                                    };
                                }
                            }
                        }
                        finish(request, token);
                    }
                    @Override public void error(String code, String message, Object details) {
                        main.removeCallbacks(timeout);
                        finish(request, null);
                    }
                    @Override public void notImplemented() {
                        main.removeCallbacks(timeout);
                        finish(request, null);
                    }
                });
            });
            return request.getTask();
        }

        private synchronized void finish(TaskCompletionSource<AppCheckToken> request,
                                         AppCheckToken token) {
            if (pending != request) return; // Ignore late timeout/callback.
            pending = null;
            if (closed || token == null) {
                request.trySetException(new Exception("HMS_VERIFICATION_UNAVAILABLE"));
            } else {
                request.trySetResult(token);
            }
        }
        synchronized void close() {
            closed = true;
            if (pending != null) finish(pending, null);
        }
    }
}
