# -*- coding: utf-8 -*-
"""
MobSF DAST API Wrapper  v3.0
All endpoints verified against official MobSF REST API docs.

Endpoint corrections from v2.0:
  /api/v1/android/instrument  → /api/v1/frida/instrument
  /api/v1/android/frida_logs  → /api/v1/frida/logs
  /api/v1/android/logcat      → /api/v1/android/logcat (param: package=, not hash=)

New endpoints added:
  /api/v1/frida/api_monitor       Live API Monitor output
  /api/v1/frida/get_dependencies  Runtime dependency list
  /api/v1/frida/list_scripts      List all available named Frida scripts
  /api/v1/frida/get_script        Fetch a named script JS code
  /api/v1/android/adb_command     Execute ADB shell commands via API
  /api/v1/android/activity        Activity tester (type=exported or type=all)
"""

import requests
import subprocess
import time
import os
import json


class MobSFTools:

    def __init__(self, server, api_key, hash_val,
                 output_dir='validation_output', package_name=''):
        self.server     = server.rstrip('/')
        self.api_key    = api_key
        self.hash       = hash_val
        self.output_dir = output_dir
        self.package    = package_name
        self.headers    = {'Authorization': api_key}
        os.makedirs(os.path.join(output_dir, 'screenshots'), exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'pcap'),        exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'logs'),        exist_ok=True)

    # ─────────────────────────────────────────
    # APP CONTROL
    # ─────────────────────────────────────────

    def launch_app(self, package=None):
        pkg = package or self.package
        print(f'  [*] Launching app: {pkg}')
        try:
            subprocess.run([
                'adb', 'shell', 'monkey', '-p', pkg,
                '-c', 'android.intent.category.LAUNCHER', '1'
            ], timeout=(5, 15), capture_output=True)
            time.sleep(3)
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def stop_app(self, package=None):
        pkg = package or self.package
        print(f'  [*] Stopping app: {pkg}')
        try:
            subprocess.run(
                ['adb', 'shell', 'am', 'force-stop', pkg],
                timeout=(5, 10), capture_output=True
            )
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def start_activity(self, activity):
        """Launch a specific activity by full class name."""
        print(f'  [*] Starting activity: {activity}')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/start_activity',
                headers=self.headers,
                data={'hash': self.hash, 'activity': activity},
                timeout=(5, 30)
            )
            resp = r.json() if r.content else {}
            if r.status_code != 200:
                return {'success': False, 'error': f'HTTP {r.status_code}: {resp}'}
            time.sleep(3)
            return {'success': True, 'response': resp}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def adb_command(self, cmd):
        """
        Execute any ADB shell command via MobSF API.
        Endpoint: /api/v1/android/adb_command
        No subprocess needed. Works inside MobSF session context.
        Examples: 'dumpsys activity', 'cat /data/data/pkg/shared_prefs/*.xml'
        """
        print(f'  [*] ADB command: {cmd[:60]}')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/adb_command',
                headers=self.headers,
                data={'cmd': cmd},
                timeout=(5, 30)
            )
            resp = r.json() if r.content else {}
            if r.status_code != 200:
                return {'success': False, 'error': f'HTTP {r.status_code}: {resp}'}
            return {'success': True, 'data': resp}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ─────────────────────────────────────────
    # ADB INPUT
    # ─────────────────────────────────────────

    def adb_input_text(self, text):
        print(f'  [*] Inputting text: {text[:30]}')
        try:
            escaped = text.replace(' ', '%s').replace("'", "\\'")
            subprocess.run(
                ['adb', 'shell', 'input', 'text', escaped],
                timeout=(5, 10), capture_output=True
            )
            time.sleep(1)
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def adb_tap(self, x, y):
        print(f'  [*] Tapping: ({x}, {y})')
        try:
            subprocess.run(
                ['adb', 'shell', 'input', 'tap', str(x), str(y)],
                timeout=(5, 10), capture_output=True
            )
            time.sleep(1)
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def adb_press_key(self, keycode):
        print(f'  [*] Pressing key: {keycode}')
        try:
            subprocess.run(
                ['adb', 'shell', 'input', 'keyevent', str(keycode)],
                timeout=(5, 10), capture_output=True
            )
            time.sleep(1)
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ─────────────────────────────────────────
    # SCREENSHOT
    # ─────────────────────────────────────────

    def take_screenshot(self, name):
        print(f'  [*] Taking screenshot: {name}')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/screenshot',
                headers=self.headers,
                data={'hash': self.hash},
                timeout=(5, 20)
            )
            if r.status_code == 200 and \
               r.headers.get('content-type', '').startswith('image'):
                path = os.path.join(
                    self.output_dir, 'screenshots', f'{name}.png')
                with open(path, 'wb') as f:
                    f.write(r.content)
                return {'success': True, 'path': path}
        except Exception:
            pass
        try:
            path = os.path.join(self.output_dir, 'screenshots', f'{name}.png')
            subprocess.run(
                ['adb', 'shell', 'screencap', '-p', f'/sdcard/{name}.png'],
                timeout=(5, 10), capture_output=True
            )
            subprocess.run(
                ['adb', 'pull', f'/sdcard/{name}.png', path],
                timeout=(5, 10), capture_output=True
            )
            subprocess.run(
                ['adb', 'shell', 'rm', f'/sdcard/{name}.png'],
                timeout=(5, 5), capture_output=True
            )
            return {'success': True, 'path': path}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ─────────────────────────────────────────
    # LOGCAT
    # FIXED: param is 'package', NOT 'hash'
    # ─────────────────────────────────────────

    def get_logcat(self, package=None):
        """
        Get Android logcat filtered to package.
        Endpoint: /api/v1/android/logcat
        FIXED in v3.0: param is 'package=' not 'hash=' (was the bug causing failures)
        """
        pkg = package or self.package
        print(f'  [*] Getting logcat for: {pkg}')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/logcat',
                headers=self.headers,
                data={'package': pkg},
                timeout=(5, 30)
            )
            resp = r.json() if r.content else {}
            if r.status_code != 200:
                return {'success': False, 'error': f'HTTP {r.status_code}: {resp}'}
            log_path = os.path.join(self.output_dir, 'logs', 'logcat.json')
            with open(log_path, 'w', encoding='utf-8') as f:
                json.dump(resp, f, indent=2)
            return {'success': True, 'data': resp, 'path': log_path}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ─────────────────────────────────────────
    # HTTP TRAFFIC
    # ─────────────────────────────────────────

    def get_http_logs(self):
        """
        Get all intercepted HTTP/HTTPS traffic.
        Proxy is always active during DAST — no start/stop pcap needed.
        """
        print('  [*] Getting HTTP logs...')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/httptools',
                headers=self.headers,
                data={'hash': self.hash},
                timeout=(5, 20)
            )
            resp = r.json() if r.content else {}
            if r.status_code != 200:
                return {'success': False, 'error': f'HTTP {r.status_code}: {resp}'}
            log_path = os.path.join(self.output_dir, 'logs', 'http_logs.json')
            with open(log_path, 'w', encoding='utf-8') as f:
                json.dump(resp, f, indent=2)
            return {'success': True, 'data': resp, 'path': log_path}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ─────────────────────────────────────────
    # FRIDA
    # FIXED: all endpoints now under /api/v1/frida/
    # ─────────────────────────────────────────

    def run_frida_script(self, default_hooks=None):
        """
        Inject Frida with default hooks.
        Endpoint: /api/v1/frida/instrument
        FIXED in v3.0: was /api/v1/android/instrument (wrong)
        """
        hooks = default_hooks or (
            'api_monitor,ssl_pinning_bypass,root_bypass,'
            'debugger_check_bypass,dump_clipboard'
        )
        print(f'  [*] Running Frida instrumentation...')
        try:
            r = requests.post(
                f'{self.server}/api/v1/frida/instrument',
                headers=self.headers,
                data={
                    'hash':            self.hash,
                    'default_hooks':   hooks,
                    'auxiliary_hooks': '',
                    'frida_code':      ''
                },
                timeout=(5, 30)
            )
            resp = r.json() if r.content else {}
            if r.status_code != 200:
                return {'success': False, 'error': f'HTTP {r.status_code}: {resp}'}
            time.sleep(5)
            logs = self.get_frida_logs()
            return {'success': True, 'response': resp, 'logs': logs.get('data', {})}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def run_named_frida_script(self, script_name):
        """
        Run a specific named Frida script.
        Available: crypto-aes-key, audit-webview, crypto-trace-cipher,
                   crypto-dump-keystore, bypass-emulator-detection, app-environment, etc.
        Steps: fetch JS via /api/v1/frida/get_script, then inject via /api/v1/frida/instrument
        """
        print(f'  [*] Running named Frida script: {script_name}')
        try:
            # Step 1: fetch the script source
            r = requests.post(
                f'{self.server}/api/v1/frida/get_script',
                headers=self.headers,
                data={'script': script_name},
                timeout=(5, 20)
            )
            if r.status_code != 200:
                return {'success': False, 'error': f'Script fetch failed: HTTP {r.status_code}'}
            script_data = r.json() if r.content else {}
            script_code = script_data.get('script', '')
            if not script_code:
                return {'success': False, 'error': f'Empty script returned for: {script_name}'}

            # Step 2: inject via frida/instrument with frida_code param
            r2 = requests.post(
                f'{self.server}/api/v1/frida/instrument',
                headers=self.headers,
                data={
                    'hash':            self.hash,
                    'default_hooks':   '',
                    'auxiliary_hooks': '',
                    'frida_code':      script_code
                },
                timeout=(5, 30)
            )
            resp = r2.json() if r2.content else {}
            if r2.status_code != 200:
                return {'success': False, 'error': f'Inject failed: HTTP {r2.status_code}: {resp}'}
            time.sleep(5)
            logs = self.get_frida_logs()
            return {'success': True, 'response': resp, 'logs': logs.get('data', {})}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_frida_logs(self):
        """
        Read Frida hook output.
        Endpoint: /api/v1/frida/logs
        FIXED in v3.0: was /api/v1/android/frida_logs (wrong)
        """
        print('  [*] Getting Frida logs...')
        try:
            r = requests.post(
                f'{self.server}/api/v1/frida/logs',
                headers=self.headers,
                data={'hash': self.hash},
                timeout=(5, 20)
            )
            resp = r.json() if r.content else {}
            if r.status_code != 200:
                return {'success': False, 'error': f'HTTP {r.status_code}: {resp}'}
            log_path = os.path.join(self.output_dir, 'logs', 'frida_logs.json')
            with open(log_path, 'w', encoding='utf-8') as f:
                json.dump(resp, f, indent=2)
            return {'success': True, 'data': resp, 'path': log_path}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_frida_api_monitor(self):
        """
        Get Live API Monitor — all Java API calls made by the app.
        Endpoint: /api/v1/frida/api_monitor
        Requires api_monitor hook active via run_frida_script first.
        """
        print('  [*] Getting Frida API monitor...')
        try:
            r = requests.post(
                f'{self.server}/api/v1/frida/api_monitor',
                headers=self.headers,
                data={'hash': self.hash},
                timeout=(5, 20)
            )
            resp = r.json() if r.content else {}
            if r.status_code != 200:
                return {'success': False, 'error': f'HTTP {r.status_code}: {resp}'}
            log_path = os.path.join(self.output_dir, 'logs', 'api_monitor.json')
            with open(log_path, 'w', encoding='utf-8') as f:
                json.dump(resp, f, indent=2)
            return {'success': True, 'data': resp, 'path': log_path}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_dependencies(self):
        """
        Get runtime library dependencies collected by Frida.
        Endpoint: /api/v1/frida/get_dependencies
        Returns third-party libraries loaded at runtime — maps to MASWE-0076.
        """
        print('  [*] Getting runtime dependencies...')
        try:
            r = requests.post(
                f'{self.server}/api/v1/frida/get_dependencies',
                headers=self.headers,
                data={'hash': self.hash},
                timeout=(5, 30)
            )
            resp = r.json() if r.content else {}
            if r.status_code != 200:
                return {'success': False, 'error': f'HTTP {r.status_code}: {resp}'}
            return {'success': True, 'data': resp}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def list_frida_scripts(self):
        """List all named Frida scripts available in this MobSF instance."""
        print('  [*] Listing available Frida scripts...')
        try:
            r = requests.post(
                f'{self.server}/api/v1/frida/list_scripts',
                headers=self.headers,
                data={'hash': self.hash},
                timeout=(5, 20)
            )
            resp = r.json() if r.content else {}
            if r.status_code != 200:
                return {'success': False, 'error': f'HTTP {r.status_code}: {resp}'}
            return {'success': True, 'data': resp}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ─────────────────────────────────────────
    # ACTIVITY TESTING
    # ─────────────────────────────────────────

    def test_exported_activities(self):
        """
        Launch all EXPORTED activities and take screenshots.
        Endpoint: /api/v1/android/activity with type=exported
        AllSafe has 2: ProxyActivity, DeepLinkTask
        """
        print('  [*] Testing exported activities...')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/activity',
                headers=self.headers,
                data={'hash': self.hash, 'type': 'exported'},
                timeout=(5, 120)
            )
            resp = r.json() if r.content else {}
            if r.status_code != 200:
                return {'success': False, 'error': f'HTTP {r.status_code}: {resp}'}
            return {'success': True, 'data': resp}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def run_activity_tester(self):
        """
        Launch ALL activities including non-exported. Takes screenshots of each.
        Endpoint: /api/v1/android/activity with type=all
        AllSafe has 4: ProxyActivity, DeepLinkTask, MainActivity, GoogleApiActivity
        """
        print('  [*] Running activity tester (all activities)...')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/activity',
                headers=self.headers,
                data={'hash': self.hash, 'type': 'all'},
                timeout=(5, 180)
            )
            resp = r.json() if r.content else {}
            if r.status_code != 200:
                return {'success': False, 'error': f'HTTP {r.status_code}: {resp}'}
            return {'success': True, 'data': resp}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ─────────────────────────────────────────
    # TLS / SSL SECURITY TESTER
    # ─────────────────────────────────────────

    def run_tls_tests(self):
        """
        Run all 4 TLS/SSL security tests (~75s).
        Endpoint: /api/v1/android/tls_tests
        Tests: Misconfiguration, Certificate Pinning, Pinning Bypass, Cleartext Traffic
        """
        print('  [*] Running TLS/SSL security tests (~75s)...')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/tls_tests',
                headers=self.headers,
                data={'hash': self.hash},
                timeout=(5, 180)
            )
            resp = r.json() if r.content else {}
            if r.status_code != 200:
                return {'success': False, 'error': f'HTTP {r.status_code}: {resp}'}
            return {'success': True, 'data': resp}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ─────────────────────────────────────────
    # TOOL LIST FOR AI
    # ─────────────────────────────────────────

    def navigate_to_finding(self, nav_entry):
        """
        Navigate to a specific app screen and trigger the vulnerability.
        Called BEFORE any Frida/logcat tools so evidence is captured
        while the relevant code path is actually executing.

        nav_entry comes from ALLSAFE_NAV_MAP in claude_agent.py.
        Steps are executed in order: launch activity, wait, tap, input, adb command.
        """
        activity = nav_entry.get('activity', '')
        actions  = nav_entry.get('actions', [])
        trigger  = nav_entry.get('what_triggers', '')

        print(f'  [NAV] Navigating to: {activity.split(".")[-1]}')
        print(f'  [NAV] Will trigger: {trigger[:80]}')

        # Step 1: launch the specific challenge activity
        if activity:
            result = self.start_activity(activity)
            if not result.get('success'):
                print(f'  [WARN] start_activity failed: {result.get("error")}')
                # Fallback: launch app and let monkey navigate
                self.launch_app()
            time.sleep(2)

        # Step 2: execute interaction steps
        for action in actions:
            atype = action.get('type')
            if atype == 'tap':
                self.adb_tap(action['x'], action['y'])
            elif atype == 'input':
                self.adb_input_text(action['text'])
            elif atype == 'key':
                self.adb_press_key(action['keycode'])
            elif atype == 'wait':
                time.sleep(action.get('seconds', 2))
            elif atype == 'adb':
                result = self.adb_command(action['cmd'])
                print(f'  [NAV] ADB: {action["cmd"][:60]} → {str(result)[:100]}')

        print(f'  [NAV] Navigation complete — vulnerability path triggered')
        return {'success': True, 'activity': activity, 'steps_executed': len(actions)}

    # ─────────────────────────────────────────
    # MANIFEST EVIDENCE (for static findings)
    # ─────────────────────────────────────────

    def get_manifest_content(self):
        """
        Fetch the decoded AndroidManifest.xml text from MobSF SAST.
        Endpoint: GET /api/v1/view_source?file=AndroidManifest.xml&hash=<hash>&type=apk
        Returns: {'success': True, 'content': '<xml string>'} or {'success': False, 'error': ...}
        """
        print('  [*] Fetching AndroidManifest.xml from MobSF SAST...')
        try:
            r = requests.get(
                f'{self.server}/api/v1/view_source',
                headers=self.headers,
                params={
                    'file': 'AndroidManifest.xml',
                    'hash': self.hash,
                    'type': 'apk',
                },
                timeout=(5, 30),
            )
            if r.status_code == 200:
                data = r.json()
                # MobSF returns: {"file": "...", "data": "<xml>", "status": "ok"}
                content = data.get('data', '') or data.get('content', '')
                if content:
                    print(f'  [OK] Manifest fetched ({len(content)} chars)')
                    return {'success': True, 'content': content}
                return {'success': False, 'error': f'Empty data in response: {list(data.keys())}'}
            return {'success': False, 'error': f'HTTP {r.status_code}'}
        except Exception as e:
            # Fallback: pull directly from device via ADB
            print(f'  [WARN] MobSF view_source failed ({e}), trying ADB pull...')
            return self._get_manifest_via_adb()

    def _get_manifest_via_adb(self):
        """
        Fallback: pull decoded manifest from device using ADB + aapt2.
        Tries: (1) cat from extracted APK location, (2) aapt2 dump, (3) apktool

        """
        try:
            # Try to get the APK path first
            r = subprocess.run(
                ['adb', 'shell', 'pm', 'path', self.package],
                capture_output=True, text=True, timeout=10
            )
            apk_path = r.stdout.strip().replace('package:', '').strip()
            if not apk_path:
                return {'success': False, 'error': 'Could not find APK path via pm path'}

            # Pull APK to temp location
            local_apk = os.path.join(self.output_dir, '_temp_app.apk')
            subprocess.run(
                ['adb', 'pull', apk_path, local_apk],
                capture_output=True, timeout=30
            )

            # Try aapt2 to dump manifest
            r2 = subprocess.run(
                ['aapt2', 'dump', 'xmltree', '--file', 'AndroidManifest.xml', local_apk],
                capture_output=True, text=True, timeout=30
            )
            if r2.returncode == 0 and r2.stdout:
                return {'success': True, 'content': r2.stdout}

            # Try aapt (v1) fallback
            r3 = subprocess.run(
                ['aapt', 'dump', 'xmltree', local_apk, 'AndroidManifest.xml'],
                capture_output=True, text=True, timeout=30
            )
            if r3.returncode == 0 and r3.stdout:
                return {'success': True, 'content': r3.stdout}

            return {'success': False, 'error': 'aapt/aapt2 not available or failed'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def manifest_screenshot(self, finding_title, highlight_keywords,
                            name=None, context_lines=8):
        """
        Capture AndroidManifest.xml as a PNG evidence screenshot with the
        relevant lines highlighted in yellow.

        Steps:
          1. Fetch manifest text via MobSF SAST API (or ADB fallback)
          2. Find lines containing any highlight_keyword
          3. Extract ±context_lines around each match
          4. Render to PNG using Pillow with:
               - Dark background (like a code editor)
               - Yellow highlight on matching lines
               - Filename + finding title as header
          5. Save to screenshots/ and return path

        Args:
            finding_title   : str — used as header text and filename
            highlight_keywords : list[str] — e.g. ['android:debuggable', 'true']
            name            : str — output filename (auto-generated if None)
            context_lines   : int — lines before/after match to include

        Returns:
            {'success': True, 'path': '/path/to/screenshot.png', 'matched_lines': [...]}
            {'success': False, 'error': '...'}
        """
        try:
            from PIL import Image, ImageDraw, ImageFont
        except ImportError:
            try:
                import subprocess as _sp
                _sp.run(['pip', 'install', 'Pillow', '--break-system-packages', '-q'],
                        capture_output=True)
                from PIL import Image, ImageDraw, ImageFont
            except Exception as e:
                return {'success': False, 'error': f'Pillow not available: {e}'}

        # ── Step 1: Get manifest content ──────────────────────────────
        result = self.get_manifest_content()
        if not result['success']:
            return result

        manifest_text = result['content']
        lines         = manifest_text.splitlines()

        # ── Step 2: Find matching lines ───────────────────────────────
        matched_indices = set()
        for i, line in enumerate(lines):
            line_lower = line.lower()
            if any(kw.lower() in line_lower for kw in highlight_keywords):
                # Include context window around match
                for j in range(max(0, i - context_lines),
                               min(len(lines), i + context_lines + 1)):
                    matched_indices.add(j)

        if not matched_indices:
            # No match found — fall back to showing first 60 lines
            print(f'  [WARN] No manifest lines matched keywords: {highlight_keywords}')
            display_indices = list(range(min(60, len(lines))))
            highlight_set   = set()
        else:
            display_indices = sorted(matched_indices)
            # Which lines in display_indices are actual matches (get yellow bg)
            highlight_set = set()
            for i, line in enumerate(lines):
                if any(kw.lower() in line.lower() for kw in highlight_keywords):
                    highlight_set.add(i)

        display_lines = [(i, lines[i]) for i in display_indices]
        matched_lines = [lines[i] for i in sorted(highlight_set)]

        print(f'  [*] Rendering manifest screenshot: {len(display_lines)} lines, '
              f'{len(highlight_set)} highlighted')

        # ── Step 3: Render PNG ────────────────────────────────────────
        # Typography
        FONT_SIZE   = 14
        LINE_HEIGHT = 20
        PADDING     = 16
        HEADER_H    = 60
        GUTTER      = 48   # line number column width

        # Try to load monospace font; fall back to PIL default
        font = header_font = None
        for font_path in [
            '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',
            '/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf',
            '/System/Library/Fonts/Menlo.ttc',
            'C:/Windows/Fonts/consola.ttf',
        ]:
            if os.path.exists(font_path):
                try:
                    font        = ImageFont.truetype(font_path, FONT_SIZE)
                    header_font = ImageFont.truetype(font_path, FONT_SIZE + 2)
                    break
                except Exception:
                    pass
        if font is None:
            font = header_font = ImageFont.load_default()

        # Canvas size
        max_chars  = max((len(l) for _, l in display_lines), default=80)
        img_width  = GUTTER + PADDING + max_chars * 8 + PADDING
        img_width  = max(img_width, 900)
        img_height = HEADER_H + len(display_lines) * LINE_HEIGHT + PADDING * 2

        # Colours
        BG_DARK    = (30,  30,  30)    # editor background
        BG_HEADER  = (20,  20,  20)    # header bar
        BG_HILIGHT = (80,  70,  0)     # yellow highlight row
        BG_GUTTER  = (40,  40,  40)    # line number background
        C_LINENO   = (100, 100, 100)   # grey line numbers
        C_TEXT     = (212, 212, 212)   # normal text
        C_HITEXT   = (255, 220, 50)    # highlighted text
        C_HEADER   = (255, 255, 255)   # header text
        C_SUBHEAD  = (150, 200, 255)   # finding subtitle
        C_BORDER   = (60,  60,  60)    # separator

        img  = Image.new('RGB', (img_width, img_height), BG_DARK)
        draw = ImageDraw.Draw(img)

        # Header bar
        draw.rectangle([0, 0, img_width, HEADER_H], fill=BG_HEADER)
        draw.line([0, HEADER_H, img_width, HEADER_H], fill=C_BORDER, width=2)
        draw.text((PADDING, 10),    'AndroidManifest.xml',    font=header_font, fill=C_HEADER)
        draw.text((PADDING, 32),    f'Evidence: {finding_title}',
                                                              font=font,        fill=C_SUBHEAD)
        draw.text((img_width - 200, 10), f'MobSF SAST Analysis',
                                                              font=font,        fill=C_LINENO)

        # Code lines
        prev_idx = None
        y = HEADER_H + PADDING
        for idx, (line_no, line_text) in enumerate(display_lines):
            real_line = line_no + 1   # 1-indexed

            # Gap indicator: show "..." if there's a break in line numbers
            if prev_idx is not None and line_no > prev_idx + 1:
                draw.text(
                    (GUTTER + PADDING // 2, y),
                    '   ···',
                    font=font, fill=C_LINENO
                )
                y += LINE_HEIGHT

            is_highlighted = line_no in highlight_set

            # Row background
            if is_highlighted:
                draw.rectangle([0, y, img_width, y + LINE_HEIGHT], fill=BG_HILIGHT)
            draw.rectangle([0, y, GUTTER, y + LINE_HEIGHT], fill=BG_GUTTER)

            # Line number
            draw.text((4, y + 3), f'{real_line:4d}', font=font, fill=C_LINENO)

            # Code text (truncate very long lines)
            text_col    = C_HITEXT if is_highlighted else C_TEXT
            display_txt = line_text.rstrip()
            if len(display_txt) > 120:
                display_txt = display_txt[:117] + '...'
            draw.text((GUTTER + PADDING // 2, y + 3), display_txt,
                      font=font, fill=text_col)

            y        += LINE_HEIGHT
            prev_idx  = line_no

        # ── Step 4: Save ──────────────────────────────────────────────
        safe_name = name or (
            'manifest_' +
            finding_title.lower()
                         .replace(' ', '_')
                         .replace('/', '_')
                         .replace(':', '')
                         [:50]
        )
        out_path = os.path.join(self.output_dir, 'screenshots', f'{safe_name}.png')
        img.save(out_path, 'PNG')
        print(f'  [OK] Manifest screenshot saved: {out_path}')
        return {
            'success':       True,
            'path':          out_path,
            'matched_lines': matched_lines,
        }

    def get_tool_list(self):
        return {
            'navigate_to_finding':      'Navigate to a specific AllSafe challenge screen and trigger the vulnerability (use finding title as key)',
            'launch_app':               'Launch app from home screen via ADB',
            'stop_app':                 'Force stop the app',
            'start_activity':           'Launch a specific activity by full class name',
            'adb_command':              'Execute any ADB shell command (e.g. dumpsys, cat shared_prefs, sqlite3)',
            'adb_input_text':           'Type text into the focused input field on screen',
            'adb_tap':                  'Tap screen at x,y pixel coordinates',
            'adb_press_key':            'Press Android key: 66=Enter, 4=Back, 3=Home',
            'take_screenshot':          'Capture current emulator screen as PNG',
            'get_logcat':               'Get Android system log for this package — crashes, debug output, data leakage',
            'get_http_logs':            'Get all intercepted HTTP/HTTPS traffic (proxy always active)',
            'run_frida_script':         'Inject default Frida hooks: API monitor, SSL bypass, root bypass, debugger bypass, clipboard monitor',
            'run_named_frida_script':   'Run a named Frida script: crypto-aes-key, audit-webview, crypto-trace-cipher, crypto-dump-keystore, bypass-emulator-detection',
            'get_frida_logs':           'Read Frida hook output (call after run_frida_script)',
            'get_frida_api_monitor':    'Get all Java API calls made by the app at runtime',
            'get_dependencies':         'Get runtime library dependencies collected by Frida',
            'test_exported_activities': 'Launch all exported activities and take screenshots',
            'run_activity_tester':      'Launch ALL activities (including hidden/non-exported) and take screenshots',
            'run_tls_tests':            'Run 4 TLS/SSL security tests: Misconfiguration, Pinning, Pinning Bypass, Cleartext (~75s)',
            'get_manifest_content':     'Fetch raw AndroidManifest.xml text from MobSF SAST (falls back to ADB+aapt2)',
            'manifest_screenshot':      'Render highlighted AndroidManifest.xml lines as PNG evidence for static findings',
        }