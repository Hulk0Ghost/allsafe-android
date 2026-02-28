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
            ], timeout=15, capture_output=True)
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
                timeout=10, capture_output=True
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
                timeout=30
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
                timeout=30
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
                timeout=10, capture_output=True
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
                timeout=10, capture_output=True
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
                timeout=10, capture_output=True
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
                timeout=20
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
                timeout=10, capture_output=True
            )
            subprocess.run(
                ['adb', 'pull', f'/sdcard/{name}.png', path],
                timeout=10, capture_output=True
            )
            subprocess.run(
                ['adb', 'shell', 'rm', f'/sdcard/{name}.png'],
                timeout=5, capture_output=True
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
                timeout=30
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
                timeout=20
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
                timeout=30
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
                timeout=20
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
                timeout=30
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
                timeout=20
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
                timeout=20
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
                timeout=30
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
                timeout=20
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
                timeout=120
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
                timeout=180
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
                timeout=180
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

    def get_tool_list(self):
        return {
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
        }