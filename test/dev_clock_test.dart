import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:mekfeya_hms_appcheck_bridge/dev_huawei_token_client.dart';

void main() {
  for (final offset in [-120, -30, 0, 1, 30, 119]) {
    test('bounded clock offset $offset keeps conservative cache', () async {
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final token = await client(now + offset, now + offset + 1800).fetchToken();
      expect(token.expiresAtMillis, lessThanOrEqualTo((now + offset + 1800) * 1000));
      expect(token.expiresAtMillis, lessThanOrEqualTo(DateTime.now().millisecondsSinceEpoch + 1740000));
      expect(token.toMessage()['token'], token.token);
    });
  }
  for (final entry in <String, List<int?>>{
    'missing issued time': [null, 1800],
    'overlong lifetime': [0, 1801],
    'zero lifetime': [0, 0],
    'expired': [-1900, -100],
    'excessive future skew': [180, 1980],
  }.entries) {
    test('reject ${entry.key}', () async {
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      await expectLater(client(entry.value[0] == null ? null : now + entry.value[0]!,
          now + entry.value[1]!).fetchToken(), throwsStateError);
    });
  }
}

DevHuaweiTokenClient client(int? issued, int expiry) {
  final claims = {'exp': expiry, if (issued != null) 'iat': issued,
    'iss': 'https://firebaseappcheck.googleapis.com/853460861480',
    'aud': ['projects/853460861480'],
    'sub': '1:853460861480:android:dcad031b3ecec2196b6b1d'};
  final token = 'header.${base64Url.encode(utf8.encode(jsonEncode(claims))).replaceAll('=', '')}.signature';
  return DevHuaweiTokenClient(publicApiKey: 'public',
    clientFactory: () => MockClient((r) async => http.Response(jsonEncode(
      jsonDecode(r.body)['operation'] == 'challenge' ? {
        'purpose': 'release', 'appId': '119433157',
        'id': '12345678-1234-1234-1234-123456789abc',
        'nonce': base64Encode(List.filled(32, 1)),
      } : {'token': token, 'ttlMillis': 1800000}), 200)),
    attest: (_) async => 'a.b.c');
}
