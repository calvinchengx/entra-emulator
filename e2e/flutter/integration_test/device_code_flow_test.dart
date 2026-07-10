// On-device e2e: full RFC 8628 device-code flow from Dart against the
// emulator — proves the emulator's protocol surface from Flutter's network
// stack on a real Android emulator / iOS simulator. The flow needs no
// browser, so it is fully automatable (unlike flutter_appauth's external
// auth session — see lib/main.dart).
//
// Run (with the emulator serving plain HTTP for device reachability):
//   TLS_ENABLED=false HOST=0.0.0.0 PORT=8443 ./entra-emulator &
//   flutter test integration_test -d <device>
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:integration_test/integration_test.dart';

import 'package:entra_emulator_e2e/emulator_config.dart';

final _stateRe = RegExp(r'name="__ee_state" value="([^"]+)"');

Map<String, dynamic> decodeJwtPayload(String jwt) {
  final payload = jwt.split('.')[1];
  return jsonDecode(
    utf8.decode(base64Url.decode(base64Url.normalize(payload))),
  ) as Map<String, dynamic>;
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('device-code flow issues verifiable tokens', (tester) async {
    final base = Uri.parse('$authorityUrl/oauth2/v2.0');

    // 1. Device authorization.
    final da = await http.post(
      base.replace(path: '${base.path}/devicecode'),
      body: {'client_id': spaClientId, 'scope': 'openid profile offline_access'},
    );
    expect(da.statusCode, 200, reason: da.body);
    final daBody = jsonDecode(da.body) as Map<String, dynamic>;
    expect(daBody['user_code'], matches(r'^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$'));

    // 2. Poll before approval -> authorization_pending.
    final tokenUri = base.replace(path: '${base.path}/token');
    final pending = await http.post(tokenUri, body: {
      'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
      'device_code': daBody['device_code'],
      'client_id': spaClientId,
    });
    expect(pending.statusCode, 400);
    expect(jsonDecode(pending.body)['error'], 'authorization_pending');

    // 3. Approve as Alice via the approval pages (cookie carried manually).
    final verifyUri = base.replace(path: '${base.path}/devicecode/verify');
    final lookup = await http.post(verifyUri, body: {
      '__ee_step': 'lookup',
      'user_code': daBody['user_code'],
    });
    var state = _stateRe.firstMatch(lookup.body)?.group(1);
    expect(state, isNotNull, reason: lookup.body);

    final signinReq = http.Request('POST', verifyUri)
      ..bodyFields = {
        '__ee_step': 'signin',
        '__ee_state': state!,
        '__ee_user': aliceId,
      };
    final signinResp = await http.Response.fromStream(await signinReq.send());
    final cookie = signinResp.headers['set-cookie']?.split(';').first;
    expect(cookie, startsWith('ee_session='), reason: 'sign-in must set the session cookie first');
    state = _stateRe.firstMatch(signinResp.body)?.group(1);
    expect(state, isNotNull, reason: signinResp.body);

    final decide = await http.post(verifyUri, headers: {'cookie': cookie!}, body: {
      '__ee_step': 'decide',
      '__ee_state': state!,
      '__ee_decision': 'approve',
    });
    expect(decide.body, contains("You're all set"), reason: decide.body);

    // 4. Poll again -> tokens for the approving user.
    final tokens = await http.post(tokenUri, body: {
      'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
      'device_code': daBody['device_code'],
      'client_id': spaClientId,
    });
    expect(tokens.statusCode, 200, reason: tokens.body);
    final tokenBody = jsonDecode(tokens.body) as Map<String, dynamic>;
    expect(tokenBody['refresh_token'], isNotNull);
    expect(tokenBody['client_info'], isNotNull);

    final idClaims = decodeJwtPayload(tokenBody['id_token'] as String);
    expect(idClaims['oid'], aliceId);
    expect(idClaims['preferred_username'], 'alice@entraemulator.dev');
    expect(idClaims['ver'], '2.0');
    expect(idClaims['iss'], '$emuOrigin/$emuTenant/v2.0');

    // 5. The access token works against the emulator Graph.
    final me = await http.get(
      Uri.parse('$emuOrigin/graph/v1.0/me'),
      headers: {'authorization': 'Bearer ${tokenBody['access_token']}'},
    );
    expect(me.statusCode, 200, reason: me.body);
    expect(jsonDecode(me.body)['userPrincipalName'], 'alice@entraemulator.dev');
  });
}
