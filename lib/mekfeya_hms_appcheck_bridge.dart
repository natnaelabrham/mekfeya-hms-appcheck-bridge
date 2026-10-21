import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// The backend must return an official Firebase App Check token, never Huawei JWS.
class BridgeToken {
  final String token;
  final int expiresAtMillis;
  const BridgeToken(this.token, this.expiresAtMillis);

  Map<String, Object> toMessage() {
    final now = DateTime.now().millisecondsSinceEpoch;
    if (token.length > 16000 ||
        !RegExp(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')
            .hasMatch(token) ||
        expiresAtMillis <= now + 1000 ||
        expiresAtMillis > now + 1800000) {
      throw StateError('HMS_INVALID_TOKEN_RESPONSE');
    }
    return {'token': token, 'expiresAtMillis': expiresAtMillis};
  }
}

enum BridgeCapability { google, missingGoogle, huaweiRequired, unavailable }

/// Safe diagnostic labels; never forward exception messages/details.
PlatformException bridgeInitializationFailure(Object error) {
  const codes = {
    'HMS_FIREBASE_INIT', 'HMS_IDENTITY_READ', 'HMS_GMS_CHECK',
    'HMS_METADATA_READ', 'HMS_FACTORY_INSTALL', 'HMS_PROJECT_MISMATCH',
    'HMS_APP_MISMATCH', 'HMS_PACKAGE_MISMATCH', 'HMS_DEBUGGABLE_DENIED',
    'HMS_SIGNER_COUNT', 'HMS_SIGNER_DENIED', 'HMS_GMS_UPDATE_REQUIRED',
    'HMS_GMS_DISABLED', 'HMS_GMS_INVALID', 'HMS_GMS_UPDATING',
    'HMS_GMS_UNAVAILABLE', 'HMS_HOST_APP_ID_REQUIRED',
    'HMS_PROVIDER_NOT_APPLICABLE',
  };
  final code = error is MissingPluginException ? 'HMS_PLUGIN_MISSING'
      : error is TimeoutException ? 'HMS_NATIVE_TIMEOUT'
      : error is PlatformException && codes.contains(error.code) ? error.code
      : 'HMS_NATIVE_INIT_FAILED';
  return PlatformException(code: code);
}

/// No provider is installed on import, plugin registration, web or iOS.
/// Keep the normal Play Integrity path for [BridgeCapability.google].
class MekfeyaAppCheckBridge {
  static const _channel = MethodChannel('com.mekfeya/app_check_bridge');
  static Future<void>? _installation;
  static Future<BridgeToken> Function()? _fetchToken;
  static Future<BridgeToken>? _pending;

  static void _requireDev(String environment, String supabaseUrl,
      String firebaseProjectId, String firebaseAppId) {
    if (kIsWeb || defaultTargetPlatform != TargetPlatform.android ||
        environment != 'Development' ||
        supabaseUrl != 'https://cuqwnrlwqwtroqngfoir.supabase.co' ||
        firebaseProjectId != 'fintracker-dev-fa037' ||
        firebaseAppId != '1:853460861480:android:dcad031b3ecec2196b6b1d') {
      throw StateError('HMS_DEV_ONLY');
    }
  }

  static Future<BridgeCapability> capability({
    required String environment,
    required String supabaseUrl,
    required String firebaseProjectId,
    required String firebaseAppId,
  }) async {
    _requireDev(environment, supabaseUrl, firebaseProjectId, firebaseAppId);
    final String? value;
    try {
      value = await _channel.invokeMethod<String>('capability')
          .timeout(const Duration(seconds: 5));
    } catch (error) {
      throw bridgeInitializationFailure(error);
    }
    return switch (value) {
      'google' => BridgeCapability.google,
      'missingGoogle' => BridgeCapability.missingGoogle,
      'huaweiRequired' => BridgeCapability.huaweiRequired,
      _ => BridgeCapability.unavailable,
    };
  }

  static Future<void> installDev({
    required String environment,
    required String supabaseUrl,
    required String firebaseProjectId,
    required String firebaseAppId,
    required Future<BridgeToken> Function() fetchToken,
  }) {
    _requireDev(environment, supabaseUrl, firebaseProjectId, firebaseAppId);
    // A second caller cannot replace a live provider's callback.
    return _installation ??= _install(fetchToken).catchError((Object error) {
      _installation = null;
      _fetchToken = null;
      throw bridgeInitializationFailure(error);
    });
  }

  static Future<void> _install(Future<BridgeToken> Function() callback) async {
    _fetchToken = callback;
    _channel.setMethodCallHandler((call) async {
      if (call.method != 'getToken') throw MissingPluginException();
      try {
        final fetch = _fetchToken;
        if (fetch == null) throw StateError('unavailable');
        final request = _pending ??= Future.sync(fetch)
            .timeout(const Duration(seconds: 23));
        try {
          return (await request).toMessage();
        } finally {
          if (identical(_pending, request)) _pending = null;
        }
      } catch (_) {
        // No upstream error text, JWS, nonce, session secret or token in logs.
        throw PlatformException(code: 'HMS_VERIFICATION_UNAVAILABLE');
      }
    });
    await _channel.invokeMethod<void>('installDev')
        .timeout(const Duration(seconds: 5));
  }
}
