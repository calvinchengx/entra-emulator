/// Emulator connection settings, injected at build/test time with
/// --dart-define. The Android emulator reaches the host at 10.0.2.2; the iOS
/// simulator shares the host network so localhost works.
library;

import 'dart:io' show Platform;

const _originOverride = String.fromEnvironment('EMU_ORIGIN');

String get emuOrigin => _originOverride.isNotEmpty
    ? _originOverride
    : 'http://${Platform.isAndroid ? '10.0.2.2' : 'localhost'}:8443';

const emuTenant = String.fromEnvironment(
  'EMU_TENANT',
  defaultValue: '11111111-1111-1111-1111-111111111111',
);

/// Seeded public SPA app (docs/03-data-model-and-seed.md).
const spaClientId = 'cccccccc-0000-0000-0000-000000000001';

/// Seeded user Alice — the device-code test approves as her.
const aliceId = 'aaaaaaaa-0000-0000-0000-000000000001';

String get authorityUrl => '$emuOrigin/$emuTenant';
