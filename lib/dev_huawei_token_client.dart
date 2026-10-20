import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:http/http.dart' as http;
import 'package:huawei_safetydetect/huawei_safetydetect.dart';
import 'mekfeya_hms_appcheck_bridge.dart';

/// Fixed Dev endpoint. Backend must be deployed and acceptance-tested before use.
/// No service credentials or Supabase user access tokens are sent to this route.
class DevHuaweiTokenClient {
  static final _uri = Uri.parse(
      'https://cuqwnrlwqwtroqngfoir.supabase.co/functions/v1/dev-huawei-release');
  final String publicApiKey;
  final http.Client Function() _clientFactory;
  final Future<String> Function(Uint8List) _attest;

  DevHuaweiTokenClient({
    required this.publicApiKey,
    http.Client Function()? clientFactory,
    Future<String> Function(Uint8List)? attest,
  }) : _clientFactory = clientFactory ?? http.Client.new,
       _attest = attest ?? ((nonce) => SafetyDetect.sysIntegrity(
           nonce, '119433157', alg: 'RS256'));

  Future<BridgeToken> fetchToken() async {
    if (publicApiKey.isEmpty) throw StateError('HMS_DEV_CONFIGURATION');
    final random = Random.secure();
    final secret = List.generate(32, (_) => random.nextInt(256))
        .map((v) => v.toRadixString(16).padLeft(2, '0')).join();
    final client = _clientFactory();
    try {
      return await _exchange(client, secret).timeout(const Duration(seconds: 22));
    } catch (_) {
      // No error text from provider, backend, JWS or HTTP response escapes.
      throw StateError('HMS_VERIFICATION_UNAVAILABLE');
    } finally {
      client.close();
    }
  }

  Future<BridgeToken> _exchange(http.Client client, String secret) async {
    final c = await _post(client, {'operation': 'challenge', 'sessionSecret': secret});
    if (c['purpose'] != 'release' || c['appId'] != '119433157' ||
        c['id'] is! String ||
        !RegExp(r'^[a-f0-9-]{36}$').hasMatch(c['id'] as String) ||
        c['nonce'] is! String ||
        !RegExp(r'^[A-Za-z0-9+/]{43}=$').hasMatch(c['nonce'] as String)) {
      throw StateError('HMS_INVALID_CHALLENGE');
    }
    final nonce = base64Decode(c['nonce'] as String);
    if (nonce.length != 32 || base64Encode(nonce) != c['nonce']) {
      throw StateError('HMS_INVALID_CHALLENGE');
    }
    final jws = await _attest(nonce).timeout(const Duration(seconds: 12));
    if (jws.isEmpty || jws.length > 48000 || jws.split('.').length != 3) {
      throw StateError('HMS_INVALID_EVIDENCE');
    }
    final response = await _post(client, {'operation': 'verify',
      'sessionSecret': secret, 'id': c['id'], 'jws': jws});
    if (response['token'] is! String || response['ttlMillis'] != 1800000) {
      throw StateError('HMS_INVALID_TOKEN_RESPONSE');
    }
    final token = response['token'] as String;
    if (token.length > 16000 || token.split('.').length != 3) {
      throw StateError('HMS_INVALID_TOKEN_RESPONSE');
    }
    // Read expiry only for SDK cache scheduling. This is NOT signature validation
    // or an authorization decision; backend verifies official Firebase JWT.
    final claims = jsonDecode(utf8.decode(
        base64Url.decode(base64Url.normalize(token.split('.')[1]))));
    if (claims is! Map || claims['exp'] is! int ||
        claims['iss'] != 'https://firebaseappcheck.googleapis.com/853460861480' ||
        claims['sub'] != '1:853460861480:android:dcad031b3ecec2196b6b1d' ||
        claims['aud'] is! List ||
        !(claims['aud'] as List).contains('projects/853460861480')) {
      throw StateError('HMS_INVALID_TOKEN_RESPONSE');
    }
    final result = BridgeToken(token, (claims['exp'] as int) * 1000);
    result.toMessage(); // Same bounded expiry/shape contract as the native bridge.
    return result;
  }

  Future<Map<String, dynamic>> _post(http.Client client, Map<String, dynamic> body) async {
    final request = http.Request('POST', _uri)
      ..followRedirects = false
      ..headers.addAll({'Content-Type': 'application/json', 'apikey': publicApiKey})
      ..body = jsonEncode(body);
    final response = await client.send(request).timeout(const Duration(seconds: 8));
    if (response.statusCode != 200) throw StateError('HMS_REQUEST_REJECTED');
    final bytes = <int>[];
    await for (final chunk in response.stream.timeout(const Duration(seconds: 8))) {
      bytes.addAll(chunk);
      if (bytes.length > 20000) throw StateError('HMS_RESPONSE_TOO_LARGE');
    }
    final result = jsonDecode(utf8.decode(bytes));
    if (result is! Map<String, dynamic>) throw StateError('HMS_INVALID_RESPONSE');
    return result;
  }
}
