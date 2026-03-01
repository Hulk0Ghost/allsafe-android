# -*- coding: utf-8 -*-
"""
Claude Agent - Groq AI Integration  v2.0
Improved prompts with Android-specific security context
Model: llama-3.3-70b-versatile
"""

import json
import requests
import os
import sys

# Fix Windows encoding + force flush for Jenkins console visibility
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
import functools
print = functools.partial(print, flush=True)


# -----------------------------------------
# ANDROID SECURITY CONTEXT
# Used to give Groq deep Android knowledge
# -----------------------------------------

ANDROID_SECURITY_CONTEXT = """
You are a senior Android penetration tester and mobile security expert with 10+ years of experience.
You have deep knowledge of:

OWASP Mobile Top 10:
- M1: Improper Platform Usage (exported components, permissions misuse)
- M2: Insecure Data Storage (SharedPrefs, SQLite, external storage, logs)
- M3: Insecure Communication (HTTP, certificate pinning, custom trust managers)
- M4: Insecure Authentication (biometric bypass, weak session tokens)
- M5: Insufficient Cryptography (ECB mode, hardcoded keys, MD5/SHA1)
- M6: Insecure Authorization (broken access control, intent hijacking)
- M7: Client Code Quality (buffer overflows, format strings, XSS in WebView)
- M8: Code Tampering (debug flags, root detection bypass)
- M9: Reverse Engineering (hardcoded secrets, obfuscation bypass)
- M10: Extraneous Functionality (hidden backdoors, test code in prod)

Android-Specific Attack Vectors:
- Intent injection / exported activity hijacking
- Content provider SQL injection
- WebView JavaScript interface attacks
- Tapjacking / overlay attacks
- Broadcast receiver abuse
- Deep link exploitation
- Certificate pinning bypass via Frida/Objection
- Root detection bypass
- Backup extraction (adb backup)
- Logcat data leakage
- Clipboard hijacking

Common False Positive Patterns:
- Reflection usage in popular libraries (Gson, Retrofit, Glide)
- Cryptography in test/debug code only
- Exported components that require caller permissions
- HTTP allowed only for localhost/loopback
- Deprecated APIs used by third-party SDKs (not app code)
- Generic boilerplate code from IDE templates
"""

# -----------------------------------------
# FRIDA SCRIPT MAP
# Maps finding keywords → exact MobSF script names
# Scripts are in: frida_scripts/android/others/
# Used to guide the AI to pick the right script
# -----------------------------------------

FRIDA_SCRIPT_MAP = {
    # ── Cryptography ──────────────────────────────────────────────────
    'aes':               'crypto-aes-key',            # Capture AES keys in use
    'hardcoded key':     'crypto-aes-key',
    'weak crypto':       'crypto-trace-cipher',        # Trace Cipher.getInstance() calls
    'ecb':               'crypto-trace-cipher',
    'des':               'crypto-trace-cipher',
    'cipher':            'crypto-trace-cipher',
    'keystore':          'crypto-dump-keystore',       # Dump Android Keystore entries
    'key generation':    'crypto-trace-keygenparameterspec',  # Trace KeyGenParameterSpec
    'keygen':            'crypto-trace-keygenparameterspec',
    'secretkey':         'crypto-trace-secretkeyfactory',     # Trace SecretKeyFactory
    'pbkdf':             'crypto-trace-secretkeyfactory',
    'keyguard':          'crypto-keyguard-credential-intent', # Keyguard credential bypass
    'ssl pinning':       'detect-ssl-pinning',         # Detect what pinning lib is used
    'certificate pin':   'detect-ssl-pinning',
    'flutter':           'ssl-bypass-flutter',         # Flutter-specific SSL bypass
    'okhttp':            'dump-okhttp-calls',          # Dump full OkHttp request/response

    # ── Storage ───────────────────────────────────────────────────────
    'sharedpref':        'trace-shared-preference',    # Trace all SharedPreference reads/writes
    'shared pref':       'trace-shared-preference',
    'preferences':       'trace-shared-preference',
    'file':              'trace-file',                 # Trace file open/read/write
    'external storage':  'trace-file',
    'internal storage':  'trace-file',
    'inputstream':       'dump-inputstream',           # Dump raw InputStream content

    # ── Network / Traffic ─────────────────────────────────────────────
    'firebase':          'dump-okhttp-calls',          # Firebase uses OkHttp
    'cleartext':         'dump-okhttp-calls',
    'http':              'dump-okhttp-calls',
    'intent':            'dump-intent',                # Dump Intent extras on send/receive
    'broadcast':         'dump-intent',
    'deep link':         'ui-deeplink-trace',          # Trace deep link handling
    'deeplink':          'ui-deeplink-trace',

    # ── WebView ───────────────────────────────────────────────────────
    'webview':           'audit-webview',              # Full WebView security audit
    'javascript interface': 'trace-javascript-interface',  # Trace addJavascriptInterface
    'webview debug':     'ui-webview-enable-debugging', # Enable WebView remote debugging
    'xss':               'audit-webview',

    # ── Platform / IPC ────────────────────────────────────────────────
    # 'exported' removed — uses test_exported_activities() via NAV_MAP, not Frida
    'activity':          'trace-intent',               # Trace Activity launch intents
    'service':           'trace-intent',
    'receiver':          'trace-intent',
    'provider':          'trace-intent',
    'reflection':        'hook-java-reflection',       # Hook reflection calls
    'json':              'hook-json',                  # Hook JSON parsing (data exposure)
    'logging':           'hook-logging',               # Hook Log.d/e/i/w calls
    'log.':              'hook-logging',

    # ── Authentication / Biometrics ───────────────────────────────────
    'biometric':         'ui-fingerprint-bypass',      # Bypass fingerprint authentication
    'fingerprint':       'ui-fingerprint-bypass',
    'flag_secure':       'ui-flag-secure-bypass',      # Bypass FLAG_SECURE (screenshot prevention)
    'screenshot':        'ui-flag-secure-bypass',

    # ── Resilience / Anti-tampering ───────────────────────────────────
    'root':              'root_bypass',                # default hook
    'emulator':          'bypass-emulator-detection',  # Bypass emulator detection
    'adb detection':     'bypass-adb-detection',       # Bypass ADB presence detection
    'react native':      'bypass-react-native-emulator-detection',
    'debugger':          'debugger_check_bypass',      # default hook
    'clipboard':         'dump_clipboard',             # default hook
    'billing':           'hook-billing',               # Hook Google Play Billing
    'bluetooth':         'trace-bluetooth',            # Trace Bluetooth API usage

    # ── Environment / Device Info ─────────────────────────────────────
    'device id':         'device-android-id',          # Get Android device ID
    'android id':        'device-android-id',
    'environment':       'app-environment',            # Dump app environment info
    'gps':               'helper-android-spoof-gps',   # Spoof GPS location

    # ── Auxiliary (class/method exploration) ──────────────────────────
    'class':             'get_loaded_classes',         # List all loaded classes (auxiliary)
    'method':            'get_methods',                # List methods of a class (auxiliary)
    'string':            'string_catch',               # Catch string operations (auxiliary)
    'constructor':       'hook-constructor',           # Hook class constructors
}

# -----------------------------------------
# SOURCE CONTEXT
# Per-source guidance + Frida script hints
# -----------------------------------------

SOURCE_CONTEXT = {
    'manifest_analysis': (
        'Focus on: exported components without permissions, debug=true, backup=true, '
        'cleartext traffic, task hijacking via launchMode. '
        'Manifest findings are CONFIGURATION FACTS — confirm from the manifest text, no Frida needed. '
        'Relevant scripts if DAST confirmation wanted: '
        'ui-deeplink-trace (deep links), trace-intent (activity/service/receiver launch).'
    ),
    'code_analysis': (
        'Focus on: actual code reachability, whether the vulnerable code path is triggered, '
        'hardcoded credentials, insecure crypto usage. '
        'CRYPTO findings → use: crypto-aes-key, crypto-trace-cipher, crypto-dump-keystore, '
        'crypto-trace-keygenparameterspec, crypto-trace-secretkeyfactory. '
        'STORAGE findings → use: trace-shared-preference, trace-file, dump-inputstream. '
        'LOGGING findings → use: hook-logging. '
        'REFLECTION findings → use: hook-java-reflection. '
        'WEBVIEW findings → use: audit-webview, trace-javascript-interface.'
    ),
    'binary_analysis': (
        'Focus on: stack protection, PIE, RELRO, anti-debugging - consider if exploitable in practice. '
        'Relevant scripts: app-environment (binary info), device-environment.'
    ),
    'network_security': (
        'Focus on: MITM feasibility, certificate pinning, TLS version, real traffic patterns. '
        'Use run_tls_tests for definitive TLS/pinning result. '
        'Relevant scripts: detect-ssl-pinning (what pinning lib is used), '
        'dump-okhttp-calls (intercept full HTTP request/response), '
        'ssl-bypass-flutter (if Flutter app), ssl-pinning-bypass (bypass generic pinning).'
    ),
    'permissions': (
        'Focus on: whether the permission is actually invoked at runtime, '
        'evidence of sensitive data being accessed. '
        'Use get_logcat to see permission-related log output. '
        'Use run_frida_script with api_monitor to capture the exact API call. '
        'Relevant scripts: hook-logging (log permission use), '
        'trace-file (storage permissions), trace-bluetooth (BLUETOOTH permission).'
    ),
    'secrets': (
        'Focus on: whether the secret grants real access (not expired/revoked/test key), '
        'scope of access, and whether it is transmitted in network traffic. '
        'Use get_http_logs to check if the key appears in HTTP requests. '
        'Relevant scripts: dump-okhttp-calls (see key in HTTP headers/body), '
        'hook-logging (key logged at runtime).'
    ),
    'firebase': (
        'Focus on: whether Firebase DB has public read/write rules. '
        'Use get_http_logs to capture the Firebase REST API call and response. '
        'Relevant scripts: dump-okhttp-calls (full Firebase HTTP request+response body), '
        'trace-shared-preference (Firebase token storage).'
    ),
    'urls': (
        'Focus on: whether HTTP endpoints transmit sensitive data, tokens, or PII. '
        'Use get_http_logs to see the actual request and response content. '
        'Relevant scripts: dump-okhttp-calls (full request/response), hook-json (JSON data).'
    ),
}

# -----------------------------------------
# FINDING KEYWORD → FRIDA SCRIPT LOOKUP
# Used to pre-select the best script before
# even calling Groq, so the AI gets a hint
# -----------------------------------------

def get_suggested_frida_scripts(finding):
    """
    Given a finding, return the top 1-3 Frida script names most relevant to it.
    Used to inject script hints into the test plan prompt.
    """
    title = finding.get('title', '').lower()
    desc  = finding.get('description', '').lower()
    text  = title + ' ' + desc

    matched = []
    seen    = set()
    for keyword, script in FRIDA_SCRIPT_MAP.items():
        if keyword in text and script not in seen:
            matched.append(script)
            seen.add(script)
        if len(matched) >= 3:
            break

    return matched


# -----------------------------------------
# AUTO VERDICT PATTERNS
# Findings that don't need ANY tools or Groq
# Confirmed purely from SAST report data
# -----------------------------------------

AUTO_VERDICT_PATTERNS = [
    # ── SDK / Android version ─────────────────────────────────────────
    {
        'keywords': ['vulnerable android', 'minsdk', 'min sdk', 'android version',
                     'can be installed on a vulnerable', 'unpatched android',
                     'android 4.', 'android 5.', 'android 6.', 'android 7.'],
        'verdict':  'CONFIRMED',
        'confidence': 'HIGH',
        'explanation': (
            'The minSdkVersion in AndroidManifest.xml allows installation on old Android versions '
            'with known unpatched CVEs. This is a static configuration fact confirmed by SAST. '
            'No DAST validation is possible or needed — you cannot dynamically test which Android '
            'versions an app allows installation on.'
        ),
        'fix': 'Increase minSdkVersion to at least 24 (Android 7.0) in build.gradle.',
    },

    # ── Binary hardening — pure static facts ──────────────────────────
    {
        'keywords': ['nx bit', 'dep enabled', 'stack canary', 'pie enabled',
                     'relro', 'rpath', 'runpath', 'fortify', 'stripped'],
        'verdict':  'CONFIRMED',
        'confidence': 'HIGH',
        'explanation': (
            'Binary hardening flags are static properties of the compiled binary. '
            'They are measured directly from the ELF headers by SAST — DAST cannot change '
            'or verify them differently. This finding is confirmed from static analysis.'
        ),
        'fix': 'Enable the missing hardening flag in your NDK build configuration.',
    },

    # ── Permission declared but not sensitive ─────────────────────────
    {
        'keywords': ['permission declared', 'uses-permission', 'normal permission'],
        'verdict':  'NEEDS_REVIEW',
        'confidence': 'MEDIUM',
        'explanation': (
            'Permission presence in the manifest is confirmed. Whether it is actively '
            'abused at runtime requires manual review of the code paths that use it.'
        ),
        'fix': 'Remove the permission if not required, or restrict access with proper checks.',
    },

    # ── App allowBackup ───────────────────────────────────────────────
    {
        'keywords': ['allowbackup', 'allow backup', 'android:allowbackup'],
        'verdict':  'CONFIRMED',
        'confidence': 'HIGH',
        'explanation': (
            'android:allowBackup=true is set in AndroidManifest.xml. '
            'This allows any USB-connected computer to extract app data via `adb backup` '
            'without root. This is a manifest configuration fact confirmed by SAST.'
        ),
        'fix': 'Set android:allowBackup="false" in AndroidManifest.xml.',
    },

    # ── Debuggable ────────────────────────────────────────────────────
    {
        'keywords': ['debuggable', 'android:debuggable'],
        'verdict':  'CONFIRMED',
        'confidence': 'HIGH',
        'explanation': (
            'android:debuggable=true is set in AndroidManifest.xml. '
            'This allows any process to attach a debugger to the app on any device. '
            'Confirmed from manifest — no DAST needed.'
        ),
        'fix': 'Remove android:debuggable or set to false. Never ship debug builds to production.',
    },

    # ── Cleartext traffic ─────────────────────────────────────────────
    {
        'keywords': ['cleartext', 'usescleartexttraffic', 'cleartexttrafficpermitted'],
        'verdict':  'CONFIRMED',
        'confidence': 'HIGH',
        'explanation': (
            'Cleartext HTTP traffic is permitted via manifest or network security config. '
            'This is a configuration fact confirmed by SAST. '
            'TLS tests (run separately) confirm the app actually makes HTTP connections.'
        ),
        'fix': 'Set android:usesCleartextTraffic="false" and configure network_security_config.xml.',
    },

    # NOTE: EXPORTED COMPONENT is intentionally NOT auto-verdicted.
    # It must go through DAST: test_exported_activities() + run_activity_tester()
    # + ADB am start to confirm each exported activity/service is actually
    # launchable without SecurityException — manifest alone is insufficient.

    # ── Dangerous permissions ─────────────────────────────────────────
    {
        'keywords': ['dangerous permission', 'uses-permission', 'read_contacts',
                     'access_fine_location', 'read_sms', 'read_call_log',
                     'record_audio', 'camera', 'write_external_storage',
                     'read_external_storage', 'get_accounts', 'use_biometric',
                     'use_fingerprint'],
        'verdict':  'CONFIRMED',
        'confidence': 'MEDIUM',
        'explanation': (
            'The app declares a dangerous permission in AndroidManifest.xml. '
            'The permission declaration itself is a static manifest fact — DAST cannot '
            'add or remove a declared permission. Whether the permission is actually '
            'used for a malicious purpose requires code review.'
        ),
        'fix': 'Remove the permission if not required. If needed, document the business justification.',
    },

    # ── User-trusted certificates / network security config ───────────
    {
        'keywords': ['user-installed certificate', 'acceptsuserscertificates',
                     'custom network security config', 'network security config',
                     'networksecurityconfig', 'user certificate trusted',
                     'user ca cert'],
        'verdict':  'CONFIRMED',
        'confidence': 'HIGH',
        'explanation': (
            'The network security config trusts user-installed CA certificates or uses '
            'a custom security config. This is a static configuration fact in '
            'network_security_config.xml confirmed by SAST. '
            'It allows MITM attacks with a user-installed proxy certificate.'
        ),
        'fix': (
            'Remove <trust-anchors> for user certificates. '
            'Only trust system CAs or implement certificate pinning.'
        ),
    },
]


def auto_verdict(finding):
    """
    Check if a finding can be auto-confirmed/denied purely from SAST data.
    Returns a verdict dict if auto-decidable, None if Groq + DAST is needed.

    Saves: Groq API calls, tool execution time, avoids pointless TLS/Frida
    runs on findings that have nothing to do with runtime behaviour.
    """
    title = finding.get('title', '').lower()
    desc  = finding.get('description', '').lower()
    text  = title + ' ' + desc

    for pattern in AUTO_VERDICT_PATTERNS:
        if any(kw in text for kw in pattern['keywords']):
            print(f'  [AUTO] Matched pattern — verdict: {pattern["verdict"]} '
                  f'(no tools needed)')
            return {
                'verdict':          pattern['verdict'],
                'confidence':       pattern['confidence'],
                'explanation':      pattern['explanation'],
                'evidence_summary': f'Auto-verdict from SAST data: {finding["description"][:200]}',
                'fix_recommendation': pattern['fix'],
                'risk_score':       7 if finding['severity'] == 'HIGH' else
                                    9 if finding['severity'] == 'CRITICAL' else 4,
                'exploitability':   'Determined from static analysis — no runtime dependency.',
                'screenshots':      [],
                'auto_verdict':     True,   # flag so reports can show source
            }
    return None  # needs full Groq + DAST pipeline


# -----------------------------------------
# APP NAVIGATION MAP
# Maps finding keywords → activity to launch
# + interactions to trigger the vulnerability
#
# Structure per entry:
#   activity  : full class name to start_activity
#   actions   : list of {type, ...} steps to execute
#     type=tap      : tap x,y coordinates
#     type=input    : type text into focused field
#     type=key      : press keycode
#     type=wait     : sleep N seconds
#     type=adb      : run adb shell command
#
# Coordinates are for a 1080x2340 screen (AllSafe on emulator).
# The AI gets this map injected into its test plan so it knows
# exactly how to navigate before calling Frida/logcat tools.
# -----------------------------------------

ALLSAFE_NAV_MAP = {

    # ══════════════════════════════════════════════════════════════════
    # STRUCTURE PER ENTRY:
    #   activity      : full class name to launch via start_activity
    #   actions       : ordered steps — tap/input/key/wait/adb
    #   evidence_tool : SINGLE tool to call after navigation
    #   evidence_cmd  : for adb type — the exact shell command
    #   confirm_if    : list of strings — ANY present in evidence = CONFIRMED
    #   deny_if       : list of strings — ANY present in evidence = FALSE_POSITIVE
    #   what_triggers : human description of what the interaction does
    #
    # Coordinates calibrated for 1080x2340 emulator (AllSafe screenshots)
    # ══════════════════════════════════════════════════════════════════

    # ── [1] Insecure Logging ──────────────────────────────────────────
    # Screen: text input "Enter your secret here..." + submit
    # Evidence: logcat — the typed secret appears in debug log output
    'insecure logging': {
        'activity':     'infosecadventures.allsafe.challenges.InsecureLogging',
        'actions': [
            {'type': 'wait',  'seconds': 2},
            {'type': 'tap',   'x': 540, 'y': 1195},  # tap input field
            {'type': 'input', 'text': 'ALLSAFE_TEST_SECRET_XK92'},
            {'type': 'tap',   'x': 540, 'y': 1380},  # tap submit / anywhere to trigger log
            {'type': 'wait',  'seconds': 2},
        ],
        'evidence_tool': 'get_logcat',
        'evidence_cmd':  None,
        'confirm_if': [
            'ALLSAFE_TEST_SECRET_XK92',  # exact string we typed appears in logcat
            'Log.d', 'Log.e', 'Log.v',   # logging calls visible
            'secret', 'input',
        ],
        'deny_if': [],
        'what_triggers': 'Type known string into input — if insecure, it appears verbatim in logcat',
    },

    # ── [2] Hardcoded Credentials ─────────────────────────────────────
    # Screen: single [INITIATE LOGIN REQUEST] button
    # Evidence: logcat — hardcoded username/password used in the request
    'hardcoded credential': {
        'activity':     'infosecadventures.allsafe.challenges.HardcodedCredentials',
        'actions': [
            {'type': 'wait', 'seconds': 2},
            {'type': 'tap',  'x': 540, 'y': 1097},   # [INITIATE LOGIN REQUEST] button
            {'type': 'wait', 'seconds': 3},
        ],
        'evidence_tool': 'get_logcat',
        'evidence_cmd':  None,
        'confirm_if': [
            'username', 'password', 'credential',
            'login', 'basic', 'Authorization',
            'aHR0cHM',                               # base64 often used to hide creds
        ],
        'deny_if': [
            'SecurityException', 'no credentials',
        ],
        'what_triggers': 'Button fires login request using hardcoded credentials — logcat captures the attempt',
    },

    # ── [3] Firebase Database ─────────────────────────────────────────
    # Screen: [QUERY DATABASE] button
    # Evidence: HTTP logs — unauthenticated 200 response from firebaseio.com
    'firebase': {
        'activity':     'infosecadventures.allsafe.challenges.FirebaseDatabase',
        'actions': [
            {'type': 'wait', 'seconds': 2},
            {'type': 'tap',  'x': 540, 'y': 1052},   # [QUERY DATABASE] button
            {'type': 'wait', 'seconds': 5},           # wait for Firebase HTTP round-trip
        ],
        'evidence_tool': 'get_http_logs',
        'evidence_cmd':  None,
        'confirm_if': [
            'firebaseio.com',                         # Firebase REST endpoint hit
            '"200"', '200',                           # successful unauthenticated read
            '.json',                                  # Firebase REST format
        ],
        'deny_if': [
            '"401"', '"403"',                         # auth enforced = not vulnerable
            'Permission denied',
        ],
        'what_triggers': 'Tapping QUERY DATABASE fires unauthenticated Firebase REST call captured by proxy',
    },

    # ── [4] Insecure Shared Preferences ──────────────────────────────
    # Screen: Username / Password / Confirm Password fields + [STORE CREDENTIALS]
    # Evidence: ADB reads SharedPrefs XML — password stored in plaintext
    'shared pref': {
        'activity':     'infosecadventures.allsafe.challenges.InsecureSharedPreferences',
        'actions': [
            {'type': 'wait',  'seconds': 2},
            {'type': 'tap',   'x': 540, 'y': 800},   # tap Username field
            {'type': 'input', 'text': 'testuser'},
            {'type': 'tap',   'x': 540, 'y': 1005},  # tap Password field
            {'type': 'input', 'text': 'PLAINTEXT_PWD_TEST99'},
            {'type': 'tap',   'x': 540, 'y': 1190},  # tap Confirm Password field
            {'type': 'input', 'text': 'PLAINTEXT_PWD_TEST99'},
            {'type': 'tap',   'x': 540, 'y': 1355},  # [STORE CREDENTIALS] button
            {'type': 'wait',  'seconds': 2},
        ],
        'evidence_tool': 'adb_command',
        'evidence_cmd':  'cat /data/data/infosecadventures.allsafe/shared_prefs/*.xml',
        'confirm_if': [
            'PLAINTEXT_PWD_TEST99',                   # our known password in plain XML
            'testuser',
            '<string name=',                          # XML SharedPrefs structure
        ],
        'deny_if': [
            'No such file',                           # prefs not created = not stored
            'Permission denied',
        ],
        'what_triggers': 'Fill form and store — ADB reads XML file directly to confirm plaintext password storage',
    },

    # ── [5] SQL Injection ────────────────────────────────────────────
    # Screen: Username + Password fields + [LOGIN] button
    # Evidence: logcat — SQLi success message or multiple rows returned
    'sql injection': {
        'activity':     'infosecadventures.allsafe.challenges.SqlInjection',
        'actions': [
            {'type': 'wait',  'seconds': 2},
            {'type': 'tap',   'x': 540, 'y': 1195},  # tap Username field
            {'type': 'input', 'text': "' OR '1'='1"},
            {'type': 'tap',   'x': 540, 'y': 1380},  # tap Password field
            {'type': 'input', 'text': 'anything'},
            {'type': 'tap',   'x': 540, 'y': 1523},  # [LOGIN] button
            {'type': 'wait',  'seconds': 2},
        ],
        'evidence_tool': 'get_logcat',
        'evidence_cmd':  None,
        'confirm_if': [
            'success', 'Welcome', 'logged in',        # login bypassed
            'OR 1=1', "OR '1'='1",                    # payload echoed in log
            'rawQuery', 'execSQL',                    # SQL execution logged
        ],
        'deny_if': [
            'invalid', 'failed', 'incorrect',         # login rejected = not vulnerable
            'PreparedStatement',                      # parameterised = not vulnerable
        ],
        'what_triggers': "Classic SQLi payload in username field — if vulnerable, login succeeds or data leaked",
    },

    # ── [6] PIN Bypass ───────────────────────────────────────────────
    # Screen: 4-digit PIN field + [VALIDATE] button
    # Evidence: logcat — Frida hook overrides PIN check return value
    'pin bypass': {
        'activity':     'infosecadventures.allsafe.challenges.PinBypass',
        'actions': [
            {'type': 'wait',  'seconds': 2},
            {'type': 'tap',   'x': 540, 'y': 1220},  # tap PIN field
            {'type': 'input', 'text': '0000'},        # wrong PIN on purpose
            {'type': 'tap',   'x': 540, 'y': 1385},  # [VALIDATE] button
            {'type': 'wait',  'seconds': 2},
        ],
        'evidence_tool': 'get_logcat',
        'evidence_cmd':  None,
        'confirm_if': [
            'checkPin', 'validatePin', 'verifyPin',   # PIN method called
            'return', 'bypass',
            'PIN', 'pin',
        ],
        'deny_if': [
            'incorrect PIN', 'wrong pin',             # not bypassable
        ],
        'what_triggers': 'Enter wrong PIN — logcat shows PIN validation method called, Frida can then override return value',
    },

    # ── [7] Root Detection ───────────────────────────────────────────
    # Evidence: logcat — root check methods called, Frida root_bypass logs each one
    'root detection': {
        'activity':     'infosecadventures.allsafe.challenges.RootDetection',
        'actions': [
            {'type': 'wait', 'seconds': 2},
            {'type': 'tap',  'x': 540, 'y': 1200},   # trigger root check
            {'type': 'wait', 'seconds': 3},
        ],
        'evidence_tool': 'get_logcat',
        'evidence_cmd':  None,
        'confirm_if': [
            'isRooted', 'checkRoot', 'su', '/system/xbin/su',
            'RootBeer', 'RootDetection',
            'Superuser', 'BusyBox',
        ],
        'deny_if': [
            'not rooted', 'root not found',
        ],
        'what_triggers': 'Trigger root check — logcat reveals which root detection methods are called',
    },

    # ── [8] Secure Flag Bypass ───────────────────────────────────────
    # Evidence: screenshot — if FLAG_SECURE is bypassable, screenshot is NOT black
    'secure flag': {
        'activity':     'infosecadventures.allsafe.challenges.SecureFlag',
        'actions': [
            {'type': 'wait', 'seconds': 3},           # let screen fully render
        ],
        'evidence_tool': 'take_screenshot',
        'evidence_cmd':  None,
        'confirm_if': [
            'screenshot_saved',                       # screenshot captured = FLAG_SECURE absent/bypassed
        ],
        'deny_if': [],
        # Note: AI must check if screenshot is entirely black (FLAG_SECURE active) or shows content
        'what_triggers': 'Take screenshot — if FLAG_SECURE blocks it, image is black; if bypassable, content visible',
    },

    # ── [9] Deep Link Exploitation ───────────────────────────────────
    # Evidence: logcat — DeepLinkTask activity launched via URI without validation
    'deep link': {
        'activity':     'infosecadventures.allsafe.challenges.DeepLinkTask',
        'actions': [
            {'type': 'wait', 'seconds': 2},
            {'type': 'adb',  'cmd': 'am start -a android.intent.action.VIEW -d "allsafe://infosecadventures/congrats"'},
            {'type': 'wait', 'seconds': 3},
        ],
        'evidence_tool': 'get_logcat',
        'evidence_cmd':  None,
        'confirm_if': [
            'DeepLinkTask',                           # activity launched
            'allsafe://',                             # URI handled
            'congrats', 'Congrats',
            'onNewIntent', 'handleDeepLink',
        ],
        'deny_if': [
            'ActivityNotFoundException',
            'Permission denied', 'No Activity found',
        ],
        'what_triggers': 'Fire allsafe:// URI via ADB — if handled without validation, DeepLinkTask launches and logcat confirms',
    },

    # ── [10] Insecure Broadcast Receiver ─────────────────────────────
    # Evidence: logcat — broadcast received without permission check
    'broadcast': {
        'activity':     'infosecadventures.allsafe.challenges.InsecureBroadcastReceiver',
        'actions': [
            {'type': 'wait', 'seconds': 2},
            {'type': 'adb',  'cmd': 'am broadcast -a infosecadventures.allsafe.INSECURE_BROADCAST'},
            {'type': 'wait', 'seconds': 2},
        ],
        'evidence_tool': 'get_logcat',
        'evidence_cmd':  None,
        'confirm_if': [
            'BroadcastReceiver', 'onReceive',         # receiver fired
            'INSECURE_BROADCAST',
            'Broadcast', 'received',
        ],
        'deny_if': [
            'SecurityException', 'Permission Denial',
            'not exported',
        ],
        'what_triggers': 'Send broadcast from ADB with no permissions — unprotected receiver fires and logcat confirms',
    },

    # ── [11] Vulnerable WebView ───────────────────────────────────────
    # Evidence: logcat — JS interface registered, file access enabled
    'webview': {
        'activity':     'infosecadventures.allsafe.challenges.VulnerableWebView',
        'actions': [
            {'type': 'wait', 'seconds': 2},
            {'type': 'tap',  'x': 540, 'y': 1200},
            {'type': 'wait', 'seconds': 3},
        ],
        'evidence_tool': 'get_logcat',
        'evidence_cmd':  None,
        'confirm_if': [
            'addJavascriptInterface',                 # JS bridge exposed
            'setJavaScriptEnabled',                   # JS enabled
            'setAllowFileAccess',                     # file access enabled
            'WebView', 'onPageFinished',
        ],
        'deny_if': [
            'WebViewClient blocked',
        ],
        'what_triggers': 'Load WebView — logcat shows whether JavaScript interface and file access are enabled',
    },

    # ── [12] Certificate Pinning ──────────────────────────────────────
    # Evidence: run_tls_tests — definitive pass/fail for pinning
    'certificate pinning': {
        'activity':     'infosecadventures.allsafe.challenges.CertificatePinning',
        'actions': [
            {'type': 'wait', 'seconds': 2},
            {'type': 'tap',  'x': 540, 'y': 1400},   # trigger network call
            {'type': 'wait', 'seconds': 4},
        ],
        'evidence_tool': 'run_tls_tests',
        'evidence_cmd':  None,
        'confirm_if': [
            'pinning_bypass', 'bypass_success',
            'no_pinning', '"pinning": false', '"pinning":false',
        ],
        'deny_if': [
            'pinning_enforced', 'bypass_failed',
            '"pinning": true', '"pinning":true',
        ],
        'what_triggers': 'Run TLS security test suite — confirms if certificate pinning is implemented and enforced',
    },

    # ── [13] Weak Cryptography ────────────────────────────────────────
    # Evidence: logcat — algorithm name logged when Cipher.getInstance() called
    'weak crypto': {
        'activity':     'infosecadventures.allsafe.challenges.WeakCryptography',
        'actions': [
            {'type': 'wait', 'seconds': 2},
            {'type': 'tap',  'x': 540, 'y': 1200},
            {'type': 'wait', 'seconds': 2},
        ],
        'evidence_tool': 'get_logcat',
        'evidence_cmd':  None,
        'confirm_if': [
            'AES/ECB',                                # ECB mode = confirmed weak
            'DES', '3DES', 'RC4', 'MD5', 'SHA1',
            'ECB', 'NoPadding',
            'Cipher.getInstance', 'SecretKeySpec',
        ],
        'deny_if': [
            'AES/GCM', 'AES/CBC',                    # strong mode = not vulnerable
            'ECDH', 'RSA/OAEP',
        ],
        'what_triggers': 'Trigger crypto operation — logcat reveals algorithm name (AES/ECB confirms weak crypto)',
    },

    # ── [14] Insecure Service ─────────────────────────────────────────
    # Evidence: logcat — service started by external ADB command without SecurityException
    'insecure service': {
        'activity':     'infosecadventures.allsafe.challenges.InsecureService',
        'actions': [
            {'type': 'wait', 'seconds': 2},
            {'type': 'adb',  'cmd': 'am startservice -n infosecadventures.allsafe/.challenges.InsecureService'},
            {'type': 'wait', 'seconds': 3},
        ],
        'evidence_tool': 'get_logcat',
        'evidence_cmd':  None,
        'confirm_if': [
            'InsecureService',                        # service started
            'onStartCommand', 'onCreate',
            'Service started',
        ],
        'deny_if': [
            'SecurityException', 'Permission Denial',
            'not exported',
        ],
        'what_triggers': 'Start service from ADB — if no permission check, it starts and logcat confirms',
    },

    # ── [15] Insecure Content Providers ──────────────────────────────
    # Evidence: adb_command — content query returns rows without permission check
    'provider': {
        'activity':     'infosecadventures.allsafe.challenges.InsecureProviders',
        'actions': [
            {'type': 'wait', 'seconds': 2},
        ],
        'evidence_tool': 'adb_command',
        'evidence_cmd':  'content query --uri content://infosecadventures.allsafe.provider/',
        'confirm_if': [
            'Row:',                                   # data rows returned = no auth
            'result=', 'name=', 'id=',
        ],
        'deny_if': [
            'Permission Denial',                      # permission enforced = not vulnerable
            'Unknown URI', 'No content provider',
        ],
        'what_triggers': 'Query content provider directly via ADB — if exported without readPermission, rows are returned',
    },

    # ── [16] Object Serialization ─────────────────────────────────────
    # Evidence: logcat — ObjectInputStream usage visible at runtime
    'serialization': {
        'activity':     'infosecadventures.allsafe.challenges.ObjectSerialization',
        'actions': [
            {'type': 'wait', 'seconds': 2},
            {'type': 'tap',  'x': 540, 'y': 1200},
            {'type': 'wait', 'seconds': 2},
        ],
        'evidence_tool': 'get_logcat',
        'evidence_cmd':  None,
        'confirm_if': [
            'ObjectInputStream', 'Serializable',
            'readObject', 'ObjectOutputStream',
            'serialVersionUID',
        ],
        'deny_if': [
            'Parcelable',                             # Parcelable is safe alternative
        ],
        'what_triggers': 'Trigger serialization operation — logcat reveals ObjectInputStream usage confirming unsafe deserialization',
    },

    # ── [17] Arbitrary Code Execution ────────────────────────────────
    # Evidence: logcat — dynamic code loading or Runtime.exec() at runtime
    'arbitrary code': {
        'activity':     'infosecadventures.allsafe.challenges.ArbitraryCodeExecution',
        'actions': [
            {'type': 'wait', 'seconds': 2},
            {'type': 'tap',  'x': 540, 'y': 1200},
            {'type': 'wait', 'seconds': 2},
        ],
        'evidence_tool': 'get_logcat',
        'evidence_cmd':  None,
        'confirm_if': [
            'Runtime.exec', 'DexClassLoader',
            'PathClassLoader', 'exec(',
            'loadDex', 'loadClass',
            'ProcessBuilder',
        ],
        'deny_if': [
            'SecurityException', 'ClassNotFoundException',
        ],
        'what_triggers': 'Trigger code execution path — logcat shows Runtime.exec() or dynamic class loading confirming ACE',
    },

    # ── [18] Exported Components ──────────────────────────────────────
    # Strategy:
    #   Step 1 — MobSF test_exported_activities() launches all exported
    #            activities via the MobSF DAST engine and takes screenshots.
    #   Step 2 — run_activity_tester() tries ALL activities (including
    #            non-exported ones) to find hidden attack surface.
    #   Step 3 — ADB manually starts each known AllSafe exported component
    #            directly from shell (simulates a rogue app).
    #   Evidence: logcat — if launched without SecurityException = CONFIRMED
    #
    # AllSafe exported components known from manifest:
    #   - infosecadventures.allsafe.ProxyActivity   (proxy/deep-link handler)
    #   - infosecadventures.allsafe.challenges.DeepLinkTask (allsafe:// scheme)
    # Both have android:exported=true and no android:permission attribute.
    'exported component': {
        'activity':     'infosecadventures.allsafe.MainActivity',  # start from home
        'actions': [
            {'type': 'wait', 'seconds': 2},
            # Step 1: ADB direct launch of ProxyActivity — no permission needed
            {'type': 'adb',  'cmd': (
                'am start -n infosecadventures.allsafe/.ProxyActivity '
                '--activity-clear-task'
            )},
            {'type': 'wait', 'seconds': 3},
            # Step 2: ADB direct launch of DeepLinkTask with a crafted URI
            {'type': 'adb',  'cmd': (
                'am start -a android.intent.action.VIEW '
                '-d "allsafe://infosecadventures/congrats" '
                '-n infosecadventures.allsafe/.challenges.DeepLinkTask'
            )},
            {'type': 'wait', 'seconds': 3},
            # Step 3: Try starting an exported service if present
            {'type': 'adb',  'cmd': (
                'am startservice -n infosecadventures.allsafe/.challenges.InsecureService'
            )},
            {'type': 'wait', 'seconds': 2},
        ],
        # Primary evidence: MobSF exported activity tester (automated)
        # This calls /api/v1/android/activity with type=exported
        # Returns list of activities it launched + screenshots
        'evidence_tool': 'test_exported_activities',
        'evidence_cmd':  None,
        'confirm_if': [
            # MobSF tester returns activity names it successfully launched
            'ProxyActivity',
            'DeepLinkTask',
            'InsecureService',
            # ADB logcat shows successful launch
            'onCreate', 'onStart', 'onResume',
            # MobSF result keys
            'activities', 'exported',
            # Generic activity launch success
            'Starting: Intent',
        ],
        'deny_if': [
            # Any of these = permission enforced = not exploitable
            'SecurityException',
            'Permission Denial',
            'not exported',
            'requires android.permission',
        ],
        'what_triggers': (
            'ADB directly launches exported activities/services without any permission — '
            'simulates a rogue app exploiting the exported component. '
            'MobSF test_exported_activities() also runs all exported components automatically.'
        ),
    },
}


def get_nav_steps(finding):
    """
    Look up navigation steps for a finding.
    Returns nav entry dict or None if no specific navigation needed.
    Checks finding title + description against NAV_MAP keys.
    """
    title = finding.get('title', '').lower()
    desc  = finding.get('description', '').lower()
    text  = title + ' ' + desc

    # Extended keyword aliases for finding titles that don't match the NAV_MAP key exactly
    ALIASES = {
        'exported activity':  'exported component',
        'exported service':   'exported component',
        'exported receiver':  'exported component',
        'exported provider':  'exported component',
        'android:exported':   'exported component',
        'cwe-926':            'exported component',
    }
    for alias, canonical in ALIASES.items():
        if alias in text and canonical in ALLSAFE_NAV_MAP:
            return ALLSAFE_NAV_MAP[canonical]

    for keyword, nav in ALLSAFE_NAV_MAP.items():
        if keyword in text:
            return nav
    return None


def evaluate_nav_evidence(nav, evidence_output):
    """
    Given a nav entry and the raw evidence string from the tool,
    check confirm_if and deny_if patterns.

    Returns:
        'CONFIRMED'      — at least one confirm_if pattern found
        'FALSE_POSITIVE' — at least one deny_if pattern found (and no confirms)
        'NEEDS_REVIEW'   — no patterns matched either way
        None             — nav has no patterns defined
    """
    if not nav:
        return None

    confirm_patterns = nav.get('confirm_if', [])
    deny_patterns    = nav.get('deny_if', [])

    if not confirm_patterns and not deny_patterns:
        return None

    evidence_lower = evidence_output.lower()

    # Check deny_if first — if clearly not vulnerable, stop
    for pattern in deny_patterns:
        if pattern.lower() in evidence_lower:
            return 'FALSE_POSITIVE'

    # Check confirm_if
    for pattern in confirm_patterns:
        if pattern.lower() in evidence_lower:
            return 'CONFIRMED'

    return 'NEEDS_REVIEW'


# -----------------------------------------
# AI AGENT CLASS
# -----------------------------------------

class ClaudeAgent:

    def __init__(self, api_key, mobsf_tools, package_name):
        self.api_key  = api_key
        self.tools    = mobsf_tools
        self.package  = package_name
        self.model    = 'llama-3.3-70b-versatile'
        self.api_url  = 'https://api.groq.com/openai/v1/chat/completions'
        self.headers  = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type':  'application/json'
        }

    # -----------------------------------------
    # CALL GROQ API
    # -----------------------------------------

    def ask_groq(self, system_prompt, user_message, max_tokens=2000):
        try:
            payload = {
                'model':       self.model,
                'max_tokens':  max_tokens,
                'temperature': 0.1,   # Low temp = more consistent verdicts
                'messages': [
                    {'role': 'system', 'content': system_prompt},
                    {'role': 'user',   'content': user_message}
                ]
            }
            r = requests.post(
                self.api_url,
                headers=self.headers,
                json=payload,
                timeout=60
            )
            response = r.json()

            if 'choices' in response:
                return response['choices'][0]['message']['content']
            else:
                print(f'  [WARN] Groq error: {response.get("error", response)}')
                return None

        except Exception as e:
            print(f'  [WARN] Groq API failed: {e}')
            return None

    # -----------------------------------------
    # STEP 1: GET TEST PLAN
    # -----------------------------------------

    def get_test_plan(self, finding, source_code_snippet=None):
        print(f'  [AI] Analyzing: {finding["title"][:55]}')

        source           = finding.get('source', 'code_analysis')
        tool_list        = json.dumps(self.tools.get_tool_list(), indent=2)
        src_context      = SOURCE_CONTEXT.get(source, '')
        suggested_scripts = get_suggested_frida_scripts(finding)

        source_section = ''
        if source_code_snippet:
            source_section = f"""
RELEVANT SOURCE CODE (use this to assess real reachability):
{source_code_snippet}
"""

        frida_hint = ''
        if suggested_scripts:
            frida_hint = f"""
SUGGESTED FRIDA SCRIPTS FOR THIS FINDING TYPE:
Based on the finding title/description, these named scripts are most relevant:
  {', '.join(suggested_scripts)}
Use run_named_frida_script with script_name="{suggested_scripts[0]}" as a priority step.
These scripts are located in frida_scripts/android/others/ inside MobSF.
"""

        system_prompt = ANDROID_SECURITY_CONTEXT + """

Your task: given a SAST finding, design a minimal but targeted DAST test plan to CONFIRM or DENY it.
Be precise. Use the minimum steps needed — don't waste API calls on irrelevant tools.

TOOL SELECTION RULES:
- manifest_analysis findings → skip Frida, use get_logcat or take_screenshot only
- network_security findings → ALWAYS include run_tls_tests
- firebase/urls findings → ALWAYS include get_http_logs (proxy captures all traffic)
- crypto/storage findings → use run_named_frida_script with the suggested script
- permissions findings → use run_frida_script (api_monitor captures permission API calls)
- For ANY finding → get_logcat is almost always useful (captures runtime data exposure)

You MUST respond with ONLY valid JSON - no markdown, no explanation, no code blocks.
"""

        user_message = f"""
FINDING TO VALIDATE:
  ID:          {finding['id']}
  Title:       {finding['title']}
  Severity:    {finding['severity']}
  CWE:         {finding['cwe']}
  OWASP:       {finding['owasp']}
  Source:      {source}
  Description: {finding['description']}
  Files:       {json.dumps(list(finding.get('files', {}).keys())[:3])}

SPECIFIC FOCUS FOR THIS SOURCE TYPE:
{src_context}
{frida_hint}
{source_section}

AVAILABLE MOBSF DAST TOOLS:
{tool_list}

APP PACKAGE: {self.package}

Design a targeted test plan. Be specific about WHAT evidence would confirm or deny this finding.
Respond with ONLY this JSON (raw, no markdown):

{{
  "test_plan": [
    {{
      "step": 1,
      "tool": "tool_name",
      "params": {{"key": "value"}},
      "reason": "exactly what this step will reveal about the finding"
    }}
  ],
  "what_to_look_for": "specific evidence that CONFIRMS the finding (exact log strings, HTTP endpoints, Frida output)",
  "false_positive_indicators": "specific evidence that suggests FALSE POSITIVE (code only in test class, library code, never executed)",
  "severity_justification": "why this severity level is or isn't appropriate for this specific app context"
}}
"""

        response = self.ask_groq(system_prompt, user_message)

        if not response:
            return self._default_test_plan(finding)

        try:
            clean = response.strip()
            if '```' in clean:
                parts = clean.split('```')
                for part in parts:
                    if part.strip().startswith('{'):
                        clean = part.strip()
                        break
                else:
                    clean = parts[1]
                    if clean.startswith('json'):
                        clean = clean[4:]

            start = clean.find('{')
            end   = clean.rfind('}') + 1
            if start != -1 and end > start:
                clean = clean[start:end]
            return json.loads(clean)
        except Exception as e:
            print(f'  [WARN] Could not parse test plan JSON: {e}')
            return self._default_test_plan(finding)

    # -----------------------------------------
    # STEP 2: EXECUTE TEST PLAN
    # -----------------------------------------

    def execute_test_plan(self, test_plan, finding_id):
        steps   = test_plan.get('test_plan', [])
        results = []
        print(f'  [*] Executing {len(steps)} DAST steps...')

        for step in steps:
            tool_name = step['tool']
            params    = step.get('params', {})
            reason    = step.get('reason', '')

            print(f'    Step {step["step"]}: {tool_name} - {reason[:60]}')
            result = self._call_tool(tool_name, params, finding_id)
            results.append({
                'step':   step['step'],
                'tool':   tool_name,
                'params': params,
                'reason': reason,
                'result': result
            })

        return results

    # -----------------------------------------
    # TOOL DISPATCHER
    # -----------------------------------------

    def _call_tool(self, tool_name, params, finding_id):
        safe_id  = finding_id.replace('/', '_').replace(' ', '_')
        dispatch = {
            # App control
            'launch_app':               lambda: self.tools.launch_app(params.get('package', self.package)),
            'stop_app':                 lambda: self.tools.stop_app(params.get('package', self.package)),
            'start_activity':           lambda: self.tools.start_activity(params.get('activity', '')),
            'adb_command':              lambda: self.tools.adb_command(params.get('cmd', '')),
            'navigate_to_finding':      lambda: self.tools.navigate_to_finding(
                                            get_nav_steps({'title': params.get('finding_title', ''),
                                                          'description': params.get('finding_title', '')})
                                            or {}
                                        ),
            # UI
            'adb_input_text':           lambda: self.tools.adb_input_text(params.get('text', '')),
            'adb_tap':                  lambda: self.tools.adb_tap(params.get('x', 500), params.get('y', 500)),
            'adb_press_key':            lambda: self.tools.adb_press_key(params.get('keycode', 66)),
            'take_screenshot':          lambda: self.tools.take_screenshot(f'{safe_id}_step{params.get("step", 1)}'),
            # Logs & traffic
            'get_logcat':               lambda: self.tools.get_logcat(),
            'get_http_logs':            lambda: self.tools.get_http_logs(),
            # Frida (working now — frida 16.1.1 x86_64 confirmed)
            'run_frida_script':         lambda: self.tools.run_frida_script(),
            'run_named_frida_script':   lambda: self.tools.run_named_frida_script(params.get('script_name', '')),
            'get_frida_logs':           lambda: self.tools.get_frida_logs(),
            'get_frida_api_monitor':    lambda: self.tools.get_frida_api_monitor(),
            'get_dependencies':         lambda: self.tools.get_dependencies(),
            # Component & network testing
            'test_exported_activities': lambda: self.tools.test_exported_activities(),
            'run_activity_tester':      lambda: self.tools.run_activity_tester(),
            'run_tls_tests':            lambda: self.tools.run_tls_tests(),
        }

        if tool_name in dispatch:
            try:
                return dispatch[tool_name]()
            except Exception as e:
                return {'success': False, 'error': str(e)}
        else:
            print(f'  [WARN] Unknown tool: {tool_name}')
            return {'success': False, 'error': f'Unknown tool: {tool_name}'}

    # -----------------------------------------
    # STEP 3: GET VERDICT (improved prompts)
    # -----------------------------------------

    def get_verdict(self, finding, test_plan, execution_results):
        print(f'  [AI] Analyzing evidence for verdict...')

        source      = finding.get('source', 'code_analysis')
        src_context = SOURCE_CONTEXT.get(source, '')

        # Build structured evidence summary
        evidence_items   = []
        screenshots      = []
        http_data        = None
        logcat_data      = None
        frida_data       = None

        for r in execution_results:
            tool   = r['tool']
            result = r['result']
            step   = r['step']

            if tool == 'take_screenshot' and result.get('success'):
                screenshots.append(result.get('path', ''))
                evidence_items.append(f'Step {step}: Screenshot captured at {result.get("path", "")}')

            elif tool == 'get_frida_api_monitor' and result.get('success'):
                data = result.get('data', {})
                evidence_items.append(f'Step {step}: API Monitor: {json.dumps(data)[:500]}')

            elif tool == 'get_dependencies' and result.get('success'):
                data = result.get('data', {})
                evidence_items.append(f'Step {step}: Runtime dependencies: {json.dumps(data)[:400]}')

            elif tool == 'adb_command' and result.get('success'):
                data = result.get('data', {})
                evidence_items.append(f'Step {step}: ADB output: {json.dumps(data)[:400]}')

            elif tool == 'run_tls_tests' and result.get('success'):
                data = result.get('data', {})
                tls_summary = json.dumps(data)[:600]
                evidence_items.append(f'Step {step}: TLS/SSL tests completed: {tls_summary}')

            elif tool == 'run_activity_tester' and result.get('success'):
                data = result.get('data', {})
                evidence_items.append(f'Step {step}: Activity tester ran - {json.dumps(data)[:300]}')

            elif tool == 'test_exported_activities' and result.get('success'):
                data = result.get('data', [])
                evidence_items.append(f'Step {step}: Exported activity tester ran - {json.dumps(data)[:300]}')

            elif tool == 'get_http_logs' and result.get('success'):
                data = result.get('data', {})
                http_data = json.dumps(data)[:800]
                evidence_items.append(f'Step {step}: HTTP traffic captured: {http_data}')

            elif tool == 'get_frida_logs' and result.get('success'):
                data = result.get('data', {})
                frida_data = json.dumps(data)[:600]
                evidence_items.append(f'Step {step}: Frida logs: {frida_data}')

            elif tool == 'get_logcat' and result.get('success'):
                data = result.get('data', {})
                logcat_data = json.dumps(data)[:600]
                evidence_items.append(f'Step {step}: Logcat: {logcat_data}')

            elif result.get('success'):
                evidence_items.append(f'Step {step}: {tool} succeeded - {json.dumps(result.get("data", {}))[:200]}')

            else:
                evidence_items.append(f'Step {step}: {tool} failed - {result.get("error", "unknown error")}')

        evidence_str = '\n'.join(evidence_items) if evidence_items else 'No DAST evidence collected'

        # ── Evidence quality pre-check ──────────────────────────────
        all_failed    = all(not r['result'].get('success') for r in execution_results) \
                        if execution_results else True
        is_manifest   = finding.get('source') == 'manifest_analysis'
        tool_failures = [
            f"{r['tool']}: {r['result'].get('error', 'no data')}"
            for r in execution_results if not r['result'].get('success')
        ]

        # Manifest findings confirmed by manifest text alone — no DAST needed
        if is_manifest and all_failed:
            print(f'  [INFO] Manifest finding — confirming from SAST data (all DAST tools failed)')
            return {
                'verdict':          'CONFIRMED',
                'confidence':       'HIGH',
                'explanation':      (
                    f'This is a manifest configuration finding. The AndroidManifest.xml '
                    f'contains {finding.get("description", finding["title"])}. '
                    f'Manifest attributes are facts — they do not require DAST confirmation. '
                    f'DAST tools failed but this does not affect the verdict.'
                ),
                'evidence_summary': f'SAST manifest analysis: {finding["description"]}',
                'fix_recommendation': f'Remove or disable the insecure manifest flag. See CWE {finding.get("cwe", "N/A")}.',
                'risk_score':       7 if finding['severity'] == 'HIGH' else
                                    9 if finding['severity'] == 'CRITICAL' else 4,
                'exploitability':   (
                    'Manifest flags take effect at install time. No special conditions needed. '
                    'Any attacker with device access can exploit this configuration.'
                ),
                'screenshots':      screenshots
            }

        # All tools failed and it is NOT a manifest finding → NEEDS_REVIEW
        if all_failed and execution_results:
            print(f'  [INFO] All DAST tools failed — setting NEEDS_REVIEW')
            return {
                'verdict':          'NEEDS_REVIEW',
                'confidence':       'LOW',
                'explanation':      (
                    f'All DAST tools failed during validation. '
                    f'This does NOT mean the finding is a false positive — '
                    f'it means there is insufficient dynamic evidence to confirm or deny it. '
                    f'Tool failures: {"; ".join(tool_failures[:3])}'
                ),
                'evidence_summary': f'All tools failed: {", ".join(tool_failures[:3])}',
                'fix_recommendation': f'Manual review required. {finding.get("description", "")}',
                'risk_score':       5,
                'exploitability':   'Unknown — requires manual testing to determine exploitability.',
                'screenshots':      screenshots
            }
        # ── End pre-check — proceed to Groq for ambiguous cases ─────

        system_prompt = ANDROID_SECURITY_CONTEXT + """

Your task: analyze the DAST evidence and deliver a precise verdict on whether this SAST finding is real.

══════════════════════════════════════════════════
CRITICAL RULE — READ BEFORE ANYTHING ELSE:
If DAST tools failed, timed out, or returned errors →
verdict MUST be NEEDS_REVIEW with LOW confidence.
NEVER give FALSE_POSITIVE because tools failed.
Tool failure = insufficient evidence, NOT proof of safety.
Absence of evidence is NOT evidence of absence.
══════════════════════════════════════════════════

MANIFEST FINDINGS RULE:
For findings from source 'manifest_analysis' — the manifest
IS the evidence. If the finding description states that
android:debuggable=true, android:allowBackup=true,
android:exported=true, or similar flags are SET in the
AndroidManifest.xml — this is CONFIRMED regardless of DAST.
These are configuration facts, not code paths.
You do NOT need DAST to confirm a manifest attribute exists.

VERDICT RULES:
- CONFIRMED:      DAST evidence actively supports the finding,
                  OR it is a manifest/config fact
- FALSE_POSITIVE: You have POSITIVE evidence the code path is
                  unreachable, guarded, library-only, or test-only
- NEEDS_REVIEW:   Evidence is ambiguous, tools failed, or finding
                  requires manual testing to confirm

CONFIDENCE RULES:
- HIGH:   Clear definitive evidence for/against
- MEDIUM: Some evidence but not conclusive
- LOW:    Tools failed or no useful data collected — always
          pair LOW confidence with NEEDS_REVIEW verdict

RISK SCORE RULES (0-10):
- 9-10: Actively exploitable, no user interaction, RCE/data theft
- 7-8:  Exploitable with some conditions, significant data exposure
- 5-6:  Requires specific conditions, limited impact
- 3-4:  Theoretical risk, hard to exploit in practice
- 1-2:  Informational / best practice violation only

You MUST respond with ONLY valid JSON - no markdown, no explanation.
"""

        user_message = f"""
ORIGINAL SAST FINDING:
  Title:       {finding['title']}
  Severity:    {finding['severity']}
  CWE:         {finding['cwe']}
  OWASP:       {finding['owasp']}
  Source:      {source}
  Description: {finding['description']}

SPECIFIC FOCUS FOR THIS FINDING TYPE:
{src_context}

WHAT WE WERE LOOKING FOR:
{test_plan.get('what_to_look_for', 'N/A')}

FALSE POSITIVE INDICATORS:
{test_plan.get('false_positive_indicators', 'N/A')}

SEVERITY JUSTIFICATION:
{test_plan.get('severity_justification', 'N/A')}

DAST EVIDENCE COLLECTED:
{evidence_str}

Based on ALL of the above, give your verdict.
Be accurate. NEEDS_REVIEW is the correct answer when evidence is insufficient.
FALSE_POSITIVE requires positive proof the finding is wrong — not just failed tools.
CONFIRMED is appropriate for manifest/config facts even without successful DAST.
Respond with ONLY this JSON (raw, no markdown):

{{
  "verdict": "CONFIRMED",
  "confidence": "HIGH",
  "explanation": "2-3 precise sentences explaining WHY this verdict - cite specific evidence or lack thereof",
  "evidence_summary": "what specific evidence confirmed or denied this finding",
  "fix_recommendation": "concrete actionable fix for this specific issue in Android",
  "risk_score": 7,
  "exploitability": "how an attacker would actually exploit this in the real world"
}}
"""

        response = self.ask_groq(system_prompt, user_message)

        if not response:
            return self._default_verdict(finding)

        try:
            clean = response.strip()
            if '```' in clean:
                parts = clean.split('```')
                for part in parts:
                    if part.strip().startswith('{'):
                        clean = part.strip()
                        break
                else:
                    clean = parts[1]
                    if clean.startswith('json'):
                        clean = clean[4:]

            start = clean.find('{')
            end   = clean.rfind('}') + 1
            if start != -1 and end > start:
                clean = clean[start:end]
            verdict              = json.loads(clean)
            verdict['screenshots'] = screenshots
            return verdict

        except Exception as e:
            print(f'  [WARN] Could not parse verdict JSON: {e}')
            return self._default_verdict(finding)

    # -----------------------------------------
    # FULL VALIDATION PIPELINE
    # -----------------------------------------

    def validate_finding(self, finding, source_code_snippet=None):
        print(f'\n{"="*55}')
        print(f'  [{finding["severity"]}] {finding["title"][:50]}')
        print(f'  Source: {finding.get("source", "unknown")} | CWE: {finding.get("cwe", "N/A")}')
        print(f'{"="*55}')

        MAX_STEPS = 4

        # ── Step 1: Navigate to challenge screen ──────────────────────
        nav = get_nav_steps(finding)
        if nav:
            print(f'  [NAV] Navigating → {nav["activity"].split(".")[-1]}')
            self.tools.navigate_to_finding(nav)
            import time as _t; _t.sleep(2)
        else:
            self.tools.launch_app()
            import time as _t; _t.sleep(2)

        # ── Step 2: Collect targeted evidence using nav evidence_tool ─
        nav_verdict   = None
        nav_evidence  = ''

        if nav and nav.get('evidence_tool'):
            tool  = nav['evidence_tool']
            cmd   = nav.get('evidence_cmd')
            print(f'  [EVIDENCE] Collecting via: {tool}')

            if tool == 'get_logcat':
                result = self.tools.get_logcat()
            elif tool == 'get_http_logs':
                result = self.tools.get_http_logs()
            elif tool == 'run_tls_tests':
                result = self.tools.run_tls_tests()
            elif tool == 'take_screenshot':
                result = self.tools.take_screenshot(
                    f'{finding["id"].replace("/","_")}_nav_evidence')
            elif tool == 'adb_command' and cmd:
                result = self.tools.adb_command(cmd)

            elif tool == 'test_exported_activities':
                # ── Exported component — 3-source evidence strategy ──────
                # Source 1: MobSF exported activity tester (automated launch)
                print('  [EVIDENCE] Step 1/3: MobSF test_exported_activities...')
                r1 = self.tools.test_exported_activities()
                exported_data = str(r1.get('data', r1.get('error', '')))

                # Source 2: MobSF run_activity_tester (ALL activities, finds hidden)
                print('  [EVIDENCE] Step 2/3: MobSF run_activity_tester (all activities)...')
                r2 = self.tools.run_activity_tester()
                all_act_data = str(r2.get('data', r2.get('error', '')))

                # Source 3: logcat after ADB launches (captured from nav actions above)
                print('  [EVIDENCE] Step 3/3: Logcat post-launch...')
                r3 = self.tools.get_logcat()
                logcat_data = str(r3.get('data', r3.get('error', '')))

                # Combine all 3 sources into one evidence string for pattern matching
                combined = '\n'.join([
                    'test_exported_activities:', exported_data,
                    'run_activity_tester:', all_act_data,
                    'logcat:', logcat_data,
                ])
                result = {
                    'success': True,
                    'data': combined,
                }
                print(f'  [EVIDENCE] Combined {len(combined)} chars from 3 sources')
            else:
                result = {'success': False, 'error': f'Unknown evidence tool: {tool}'}

            if result.get('success'):
                # Flatten evidence to string for pattern matching
                data = result.get('data', result.get('output', result.get('path', '')))
                nav_evidence = str(data) if data else ''

                # Pattern match against confirm_if / deny_if
                nav_verdict = evaluate_nav_evidence(nav, nav_evidence)
                print(f'  [MATCH]  Pattern match → {nav_verdict}')

                # Short-circuit: deterministic result, skip Groq entirely
                if nav_verdict in ('CONFIRMED', 'FALSE_POSITIVE'):
                    print(f'  [FAST]   Deterministic verdict — skipping Groq API call')
                    confirm_patterns = [p for p in nav.get('confirm_if', [])
                                        if p.lower() in nav_evidence.lower()]
                    deny_patterns    = [p for p in nav.get('deny_if', [])
                                        if p.lower() in nav_evidence.lower()]
                    matched = confirm_patterns or deny_patterns

                    verdict = {
                        'verdict':           nav_verdict,
                        'confidence':        'HIGH',
                        'explanation':       (
                            f'Pattern match on {tool} output. '
                            f'Matched strings: {matched}. '
                            f'{nav["what_triggers"]}'
                        ),
                        'evidence_summary':  f'{tool} output matched: {matched}',
                        'fix_recommendation': finding.get('description', ''),
                        'risk_score':        7 if finding['severity'] == 'HIGH' else
                                             9 if finding['severity'] == 'CRITICAL' else 4,
                        'exploitability':    f'Confirmed at runtime via {tool}.',
                        'screenshots':       [],
                        'nav_matched':       True,
                    }
                    print(f'\n  [RESULT] {verdict["verdict"]} ({verdict["confidence"]}) | '
                          f'Risk: {verdict["risk_score"]}/10')
                    return {'finding': finding, 'test_plan': {}, 'execution': [], 'verdict': verdict}
            else:
                print(f'  [WARN]   Evidence tool failed: {result.get("error")}')
        # ── End evidence collection ───────────────────────────────────

        # ── Step 3: Groq + full test plan (ambiguous / no nav match) ──
        test_plan = self.get_test_plan(finding, source_code_snippet)

        if 'test_plan' in test_plan and len(test_plan['test_plan']) > MAX_STEPS:
            print(f'  [INFO] Capping test plan: {len(test_plan["test_plan"])} → {MAX_STEPS} steps')
            test_plan['test_plan'] = test_plan['test_plan'][:MAX_STEPS]

        # Inject nav evidence into prompt so Groq has the data even if no pattern matched
        if nav_evidence:
            test_plan['_nav_evidence']      = nav_evidence[:1000]
            test_plan['_nav_evidence_tool'] = nav.get('evidence_tool', '')
            test_plan['_nav_verdict_hint']  = nav_verdict or 'no_pattern_match'

        execution_results = self.execute_test_plan(test_plan, finding['id'])
        verdict           = self.get_verdict(finding, test_plan, execution_results)

        print(f'\n  [RESULT] {verdict["verdict"]} (Confidence: {verdict["confidence"]}) | '
              f'Risk: {verdict.get("risk_score", "?")}/10')
        print(f'  {verdict["explanation"][:100]}')

        return {
            'finding':   finding,
            'test_plan': test_plan,
            'execution': execution_results,
            'verdict':   verdict
        }

    # -----------------------------------------
    # DEFAULTS (when API fails)
    # -----------------------------------------

    def _default_test_plan(self, finding):
        return {
            'test_plan': [
                {'step': 1, 'tool': 'launch_app',      'params': {'package': self.package}, 'reason': 'Launch app for basic validation'},
                {'step': 2, 'tool': 'take_screenshot',  'params': {'step': 1},               'reason': 'Capture app state'}
            ],
            'what_to_look_for':          'General app behavior and error states',
            'false_positive_indicators': 'Groq API unavailable - manual review required',
            'severity_justification':    'Could not assess - Groq API unavailable'
        }

    def _default_verdict(self, finding):
        return {
            'verdict':          'NEEDS_REVIEW',
            'confidence':       'LOW',
            'explanation':      'Groq API unavailable. Manual review required for this finding.',
            'evidence_summary': 'No AI analysis performed - API error',
            'fix_recommendation': f'Manually review: {finding.get("description", "")}',
            'risk_score':       5,
            'exploitability':   'Unknown - requires manual assessment',
            'screenshots':      []
        }