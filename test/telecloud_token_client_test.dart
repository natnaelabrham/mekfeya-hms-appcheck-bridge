import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:mekfeya_hms_appcheck_bridge/telecloud_huawei_token_client.dart';

void main() {
  String fakeToken({String project = '529220246645'}) {
    final body = base64Url
        .encode(utf8.encode(jsonEncode({
          'exp': DateTime.now().millisecondsSinceEpoch ~/ 1000 + 1700,
          'iss': 'https://firebaseappcheck.googleapis.com/$project',
          'aud': ['projects/$project'],
          'sub': '1:529220246645:android:bda15c864075e44d56ac3c',
        })))
        .replaceAll('=', '');
    return 'header.$body.signature';
  }

  Map<String, Object> challenge() => {
        'purpose': 'release',
        'appId': '119427631',
        'id': '12345678-1234-1234-1234-123456789abc',
        'nonce': base64Encode(List.filled(32, 1)),
      };
  test('fixed Telecloud route, memory-only binding and official-token shape handoff',
      () async {
    final requests = <Map<String, dynamic>>[];
    final client = TelecloudHuaweiTokenClient(
        publicApiKey: 'public-test-key',
        clientFactory: () => MockClient((request) async {
              expect(request.url.host, 'telecloud.mekfeya.com');
              expect(request.url.path, '/functions/v1/huawei-release');
              expect(request.followRedirects, false);
              expect(request.headers.containsKey('authorization'), false);
              final body = jsonDecode(request.body) as Map<String, dynamic>;
              requests.add(body);
              return http.Response(
                  jsonEncode(body['operation'] == 'challenge'
                      ? challenge()
                      : {'token': fakeToken(), 'ttlMillis': 1800000}),
                  200);
            }),
        attest: (nonce) async {
          expect(nonce.length, 32);
          return 'huawei.synthetic.evidence';
        });
    final token = await client.fetchToken();
    expect(token.token.split('.').length, 3);
    expect(requests.length, 2);
    expect(requests[0]['sessionSecret'], matches(RegExp(r'^[a-f0-9]{64}$')));
    expect(requests[0]['sessionSecret'], requests[1]['sessionSecret']);
  });
  test('diagnostic challenge cannot invoke Huawei SDK or release exchange',
      () async {
    var calls = 0;
    final client = TelecloudHuaweiTokenClient(
        publicApiKey: 'public',
        clientFactory: () => MockClient((_) async => http.Response(
            jsonEncode({...challenge(), 'purpose': 'diagnostic'}), 200)),
        attest: (_) async {
          calls++;
          return 'a.b.c';
        });
    await expectLater(client.fetchToken(), throwsStateError);
    expect(calls, 0);
  });
  test('HTTP rejection does not retry or expose provider response', () async {
    var calls = 0;
    final client = TelecloudHuaweiTokenClient(
        publicApiKey: 'public',
        clientFactory: () => MockClient((_) async {
              calls++;
              return http.Response('private-upstream-error', 403);
            }));
    await expectLater(
        client.fetchToken(),
        throwsA(predicate(
            (e) => e.toString() == 'Bad state: HMS_VERIFICATION_UNAVAILABLE')));
    expect(calls, 1);
    expect(TelecloudHuaweiTokenClient.lastDiagnostic, 'HMS_CHALLENGE_HTTP_403');
  });
  test('Dev token cannot be delivered to Telecloud SDK', () async {
    final client = TelecloudHuaweiTokenClient(
        publicApiKey: 'public',
        clientFactory: () => MockClient((r) async => http.Response(
            jsonEncode(jsonDecode(r.body)['operation'] == 'challenge'
                ? challenge()
                : {
                    'token': fakeToken(project: '853460861480'),
                    'ttlMillis': 1800000
                  }),
            200)),
        attest: (_) async => 'a.b.c');
    await expectLater(client.fetchToken(), throwsStateError);
    expect(TelecloudHuaweiTokenClient.lastDiagnostic, 'HMS_TOKEN_FAILED');
  });
  test('numeric Huawei error survives without message or details', () async {
    final client = TelecloudHuaweiTokenClient(
        publicApiKey: 'public',
        clientFactory: () => MockClient(
            (_) async => http.Response(jsonEncode(challenge()), 200)),
        attest: (_) async => throw PlatformException(
            code: '907135000',
            message: 'PRIVATE TOKEN',
            details: 'PRIVATE NONCE'));
    await expectLater(client.fetchToken(), throwsStateError);
    expect(TelecloudHuaweiTokenClient.lastDiagnostic, 'HMS_SDK_907135000');
  });
  test('arbitrary SDK codes cannot leak into diagnostics', () async {
    final client = TelecloudHuaweiTokenClient(
        publicApiKey: 'public',
        clientFactory: () => MockClient(
            (_) async => http.Response(jsonEncode(challenge()), 200)),
        attest: (_) async => throw PlatformException(code: 'secret-token'));
    await expectLater(client.fetchToken(), throwsStateError);
    expect(TelecloudHuaweiTokenClient.lastDiagnostic, 'HMS_SDK_FAILED');
  });
  test('verify rejection is distinct from challenge and SDK failures',
      () async {
    final client = TelecloudHuaweiTokenClient(
        publicApiKey: 'public',
        clientFactory: () => MockClient((r) async =>
            jsonDecode(r.body)['operation'] == 'challenge'
                ? http.Response(jsonEncode(challenge()), 200)
                : http.Response('private', 503)),
        attest: (_) async => 'a.b.c');
    await expectLater(client.fetchToken(), throwsStateError);
    expect(TelecloudHuaweiTokenClient.lastDiagnostic, 'HMS_VERIFY_HTTP_503');
  });
}
