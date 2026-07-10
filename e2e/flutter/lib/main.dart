import 'package:flutter/material.dart';
import 'package:flutter_appauth/flutter_appauth.dart';

import 'emulator_config.dart';

/// Manual-verification app: taps through the flutter_appauth Authorization
/// Code + PKCE flow against the emulator. The auth session opens an external
/// system browser, which automated integration tests cannot drive — the
/// automated on-device coverage lives in integration_test/ (device-code
/// flow). Run the emulator, then: flutter run --dart-define=EMU_ORIGIN=...
void main() => runApp(const E2EApp());

class E2EApp extends StatelessWidget {
  const E2EApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(home: SignInScreen());
  }
}

class SignInScreen extends StatefulWidget {
  const SignInScreen({super.key});

  @override
  State<SignInScreen> createState() => _SignInScreenState();
}

class _SignInScreenState extends State<SignInScreen> {
  final _appAuth = const FlutterAppAuth();
  String _status = 'Not signed in';

  Future<void> _signIn() async {
    setState(() => _status = 'Signing in…');
    try {
      final result = await _appAuth.authorizeAndExchangeCode(
        AuthorizationTokenRequest(
          spaClientId,
          'com.entraemulator.e2e://auth',
          serviceConfiguration: AuthorizationServiceConfiguration(
            authorizationEndpoint: '$authorityUrl/oauth2/v2.0/authorize',
            tokenEndpoint: '$authorityUrl/oauth2/v2.0/token',
            endSessionEndpoint: '$authorityUrl/oauth2/v2.0/logout',
          ),
          scopes: ['openid', 'profile', 'email', 'offline_access'],
        ),
      );
      setState(() => _status =
          'Signed in. access_token: ${result.accessToken?.substring(0, 24)}…');
    } catch (e) {
      setState(() => _status = 'Failed: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Entra Emulator e2e')),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Text('Authority: $authorityUrl', textAlign: TextAlign.center),
            const SizedBox(height: 16),
            FilledButton(
              onPressed: _signIn,
              child: const Text('Sign in with flutter_appauth'),
            ),
            const SizedBox(height: 16),
            Padding(
              padding: const EdgeInsets.all(16),
              child: Text(_status, textAlign: TextAlign.center),
            ),
          ],
        ),
      ),
    );
  }
}
