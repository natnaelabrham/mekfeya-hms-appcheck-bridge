Mekfeya HMS App Check bridge — Dev integration candidate

STATUS
This is not a general-purpose or production-ready attestation package.
Version 0.1.0-dev.1 installs a native Firebase AppCheckProvider in the registered
Development Android release only. Telecloud and Production are rejected.
Successful compilation and synthetic tests are not physical-device acceptance.

WHAT IT DOES
- Registers through Flutter's normal plugin registration; no main.dart changes.
- Keeps Android Gradle configuration inside the plugin, not the host app.
- Requires the exact Dev Firebase identity, package and release signing certificate.
- Rejects debuggable apps, unexpected signers and missing Huawei host App ID.
- Allows installation only when Google Play Services reports SERVICE_MISSING.
  Disabled, outdated, invalid or updating GMS does not select Huawei.
- Supplies official server-issued Firebase App Check tokens to the native SDK,
  including its callable-function consumers, rather than only HTTP headers.
- Deduplicates pending native and Dart requests; bounds callbacks and token expiry.
- Does not change device policies, user authentication, roles, financial leases,
  enforcement, startup routes or submission gates.

The Firebase SDK owns token caching and refresh. This plugin does not add token
persistence. Native caches are NOT a replacement for the existing 30-second
financial verification lease or local policy checks.

DEPENDENCY
FlutterFlow supports Git-hosted plugins in Custom Dependencies. Use:

mekfeya_hms_appcheck_bridge:
  git:
    url: https://github.com/natnaelabrham/mekfeya-hms-appcheck-bridge.git
    ref: <tested immutable commit SHA>

Do not use a local path in FlutterFlow's cloud build. A moving main branch is
convenient during development but is not recommended for a controlled release.
No GitHub token is required to fetch this public repository.

NATIVE HOST PREREQUISITE
The Development host application's <application> needs:

<meta-data android:name="com.huawei.hms.client.appid"
           android:value="appid=119433157" />

Set this through FlutterFlow's supported AndroidManifest Application Component
Tags / environment-aware configuration. Do not unlock host Gradle or edit
main.dart. Do not insert this Dev literal into shared Production/Telecloud output.
An environment-specific value or isolated Dev project/branch must be verified.
This plugin intentionally does not inject a global Huawei App ID.

CALLER CONTRACT
1. Firebase must already be initialized, as in the current startup action.
2. Keep existing environment checks and local device-security checks.
3. Development Android release only: call MekfeyaAppCheckBridge.capability.
4. google: retain normal FirebaseAppCheck.activate(PlayIntegrity).
5. missingGoogle: installDev with DevHuaweiTokenClient.fetchToken as callback.
6. unavailable: fail closed; do not try Huawei after a Google verification failure.
7. Never call FirebaseAppCheck.activate again over the installed custom provider.
8. Continue normal FirebaseAppCheck.getToken and the existing financial verifier.
   No Huawei JWS is accepted as an App Check token.
9. Web/iOS/Telecloud/Production remain on their previous branches unchanged.
10. Do not use the bridge if the release endpoint is disabled or unvalidated.

TESTS
flutter test
flutter analyze

Native Android policy tests and release AAR compilation also require a Flutter
host harness containing firebase_core 3.14.0 and firebase_app_check 0.3.2+7:
./gradlew :mekfeya_hms_appcheck_bridge:testDebugUnitTest \
          :mekfeya_hms_appcheck_bridge:assembleRelease

RELEASE GATE
Before Telecloud promotion: one release-signed Huawei test must prove an official
Dev token, existing dev-financial-verify acceptance and an authenticated lease.
Also test Google Play Integrity, logout/account change, offline/resume behavior
and Firebase callable consumers. Never auto-resubmit financial transactions.
Diagnostic PASS alone does not satisfy this gate.

No keys, passwords, service credentials or backend issuer implementation belong
in this public repository.

References:
https://firebase.google.com/docs/app-check/android/custom-provider
https://docs.flutterflow.io/concepts/advanced/method-channels/
