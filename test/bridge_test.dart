import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mekfeya_hms_appcheck_bridge/mekfeya_hms_appcheck_bridge.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('com.mekfeya/app_check_bridge');
  var calls = 0;
  setUp(() {
    debugDefaultTargetPlatformOverride = TargetPlatform.android;
    calls = 0;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (_) async { calls++; return 'missingGoogle'; });
  });
  tearDown(() {
    debugDefaultTargetPlatformOverride = null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });
  Future<BridgeCapability> capability(String environment, {String? url}) =>
      MekfeyaAppCheckBridge.capability(environment: environment,
        supabaseUrl: url ?? 'https://cuqwnrlwqwtroqngfoir.supabase.co',
        firebaseProjectId: 'fintracker-dev-fa037',
        firebaseAppId: '1:853460861480:android:dcad031b3ecec2196b6b1d');

  test('Telecloud and Production rejected before native call', () async {
    await expectLater(capability('Telecloud'), throwsStateError);
    await expectLater(capability('Production'), throwsStateError);
    expect(calls, 0);
  });
  test('backend mismatch rejected before native call', () async {
    await expectLater(capability('Development', url: 'https://telecloud.mekfeya.com'),
        throwsStateError);
    expect(calls, 0);
  });
  test('Dev capability passed through', () async {
    expect(await capability('Development'), BridgeCapability.missingGoogle);
    expect(calls, 1);
  });
  test('invalid GMS selects an explicit Huawei attempt, not an access grant', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (_) async { calls++; return 'huaweiRequired'; });
    expect(await capability('Development'), BridgeCapability.huaweiRequired);
    await expectLater(capability('Telecloud'), throwsStateError);
    await expectLater(capability('Production'), throwsStateError);
    expect(calls, 1); // Only the Development lookup reached the native channel.
  });
  test('safe native failure is preserved without messages or details', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (_) async {
          throw PlatformException(code: 'HMS_GMS_INVALID',
              message: 'sensitive upstream text', details: {'token': 'secret'});
        });
    await expectLater(capability('Development'),
        throwsA(isA<PlatformException>()
            .having((e) => e.code, 'code', 'HMS_GMS_INVALID')
            .having((e) => e.message, 'message', isNull)
            .having((e) => e.details, 'details', isNull)));
  });
  test('unexpected errors and missing plugin are bounded and redacted', () {
    expect(bridgeInitializationFailure(
        PlatformException(code: 'secret', message: 'secret')).code,
        'HMS_NATIVE_INIT_FAILED');
    expect(bridgeInitializationFailure(MissingPluginException('secret')).code,
        'HMS_PLUGIN_MISSING');
    expect(bridgeInitializationFailure(TimeoutException('secret')).code,
        'HMS_NATIVE_TIMEOUT');
  });
  test('failed installation preserves safe reason and permits retry', () async {
    var installs = 0;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (_) async {
          installs++;
          throw PlatformException(code: 'HMS_FACTORY_INSTALL', message: 'secret');
        });
    for (var i = 0; i < 2; i++) {
      await expectLater(MekfeyaAppCheckBridge.installDev(
          environment: 'Development',
          supabaseUrl: 'https://cuqwnrlwqwtroqngfoir.supabase.co',
          firebaseProjectId: 'fintracker-dev-fa037',
          firebaseAppId: '1:853460861480:android:dcad031b3ecec2196b6b1d',
          fetchToken: () async => throw StateError('must not fetch')),
          throwsA(isA<PlatformException>()
              .having((e) => e.code, 'code', 'HMS_FACTORY_INSTALL')
              .having((e) => e.message, 'message', isNull)));
    }
    expect(installs, 2);
  });
  test('unknown native capability cannot authorize fallback', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (_) async => 'disabled');
    expect(await capability('Development'), BridgeCapability.unavailable);
  });
  test('iOS cannot invoke native bridge', () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
    await expectLater(capability('Development'), throwsStateError);
    expect(calls, 0);
  });
  test('bounded token transport; does not validate signatures', () {
    final now = DateTime.now().millisecondsSinceEpoch;
    expect(BridgeToken('a.b.c', now + 10000).toMessage()['token'], 'a.b.c');
    expect(() => BridgeToken('invalid', now + 10000).toMessage(), throwsStateError);
    expect(() => BridgeToken('a.b.c', now - 1).toMessage(), throwsStateError);
    expect(() => BridgeToken('a.b.c', now + 3600000).toMessage(), throwsStateError);
  });
}
