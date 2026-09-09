// Copyright 2014 The Flutter Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// THE DART INTEGRATION TESTS, RUN AS XCTests.
//
// This target used to hold the stock `testExample()` stub, which asserted
// nothing, while the Dart tests were driven separately by
// `flutter test integration_test -d <udid>`. That command is the path for a
// developer's own Mac: it launches the app and then DISCOVERS the Dart VM
// service by reading the simulator's unified log, because it also passes
// `--disable-vm-service-publication` so there is no mDNS to fall back on.
// A live log stream has no history and no retry, so when it misses the one
// line announcing the URL, `flutter test` waits forever -- observed on roughly
// half of nightly runs, and confirmed in run 34327775534, where the app
// published its URL 1.8s after flutter began waiting and flutter never saw it.
//
// This macro is the path the integration_test package documents for iOS, and
// it removes the failure mode rather than mitigating it: the Dart tests are
// hosted INSIDE XCTest, so xcodebuild reports each one as a native test
// result and nothing has to find a VM service over the device log.
@import XCTest;
@import integration_test;

INTEGRATION_TEST_IOS_RUNNER(RunnerTests)
