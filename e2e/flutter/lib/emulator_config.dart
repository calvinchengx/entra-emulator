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
  defaultValue: '6f89cf12-978b-4d23-ac18-9ef0c127cf87',
);

/// Seeded public SPA app (docs/03-data-model-and-seed.md).
const spaClientId = '189c7070-78a3-4c13-aa18-20a2ca5755ca';

/// Seeded user Alice — the device-code test approves as her.
const aliceId = 'df8ec5dd-1599-45ef-908b-4ae020cd1dbe';

String get authorityUrl => '$emuOrigin/$emuTenant';
