# -*- coding: utf-8 -*-
"""
MobSF DAST API Wrapper
All MobSF tools AI can use for validation
"""

import requests
import subprocess
import time
import os


class MobSFTools:

    def __init__(self, server, api_key, hash_val, output_dir='validation_output', package_name=''):
        self.server        = server.rstrip('/')
        self.api_key       = api_key
        self.hash          = hash_val
        self.output_dir    = output_dir
        self._package_name = package_name
        self.headers       = {'Authorization': api_key}
        os.makedirs(os.path.join(output_dir, 'screenshots'), exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'pcap'),        exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'logs'),        exist_ok=True)

    # -----------------------------------------
    # APP CONTROL
    # -----------------------------------------

    def start_activity(self, activity):
        print(f'  [*] Starting activity: {activity}')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/start_activity',
                headers=self.headers,
                data={'hash': self.hash, 'activity': activity},
                timeout=30
            )
            time.sleep(3)
            return {'success': True, 'response': r.json()}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def launch_app(self, package):
        print(f'  [*] Launching app: {package}')
        try:
            subprocess.run([
                'adb', 'shell', 'monkey', '-p', package,
                '-c', 'android.intent.category.LAUNCHER', '1'
            ], timeout=15, capture_output=True)
            time.sleep(3)
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def stop_app(self, package):
        print(f'  [*] Stopping app: {package}')
        try:
            subprocess.run([
                'adb', 'shell', 'am', 'force-stop', package
            ], timeout=10, capture_output=True)
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # -----------------------------------------
    # ADB INPUT
    # -----------------------------------------

    def adb_input_text(self, text):
        print(f'  [*] Inputting text: {text[:30]}')
        try:
            escaped = text.replace(' ', '%s').replace("'", "\\'")
            subprocess.run([
                'adb', 'shell', 'input', 'text', escaped
            ], timeout=10, capture_output=True)
            time.sleep(1)
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def adb_tap(self, x, y):
        print(f'  [*] Tapping: ({x}, {y})')
        try:
            subprocess.run([
                'adb', 'shell', 'input', 'tap', str(x), str(y)
            ], timeout=10, capture_output=True)
            time.sleep(1)
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def adb_press_key(self, keycode):
        print(f'  [*] Pressing key: {keycode}')
        try:
            subprocess.run([
                'adb', 'shell', 'input', 'keyevent', str(keycode)
            ], timeout=10, capture_output=True)
            time.sleep(1)
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # -----------------------------------------
    # SCREENSHOT
    # -----------------------------------------

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
                print(f'  [OK] Screenshot saved: {path}')
                return {'success': True, 'path': path}
        except Exception:
            pass

        # Fallback to ADB
        try:
            subprocess.run([
                'adb', 'shell', 'screencap', '-p',
                f'/sdcard/{name}.png'
            ], timeout=10, capture_output=True)

            path = os.path.join(
                self.output_dir, 'screenshots', f'{name}.png')

            subprocess.run([
                'adb', 'pull', f'/sdcard/{name}.png', path
            ], timeout=10, capture_output=True)

            subprocess.run([
                'adb', 'shell', 'rm', f'/sdcard/{name}.png'
            ], timeout=5, capture_output=True)

            print(f'  [OK] Screenshot saved via ADB: {path}')
            return {'success': True, 'path': path}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # -----------------------------------------
    # NETWORK CAPTURE
    # -----------------------------------------

    def start_pcap(self):
        print('  [*] Starting network capture...')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/start_pcap',
                headers=self.headers,
                data={'hash': self.hash},
                timeout=20
            )
            resp = r.json() if r.content else {}
            if r.status_code != 200:
                return {'success': False, 'error': f'HTTP {r.status_code}: {resp}'}
            return {'success': True, 'response': resp}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def stop_pcap(self):
        print('  [*] Stopping network capture...')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/stop_pcap',
                headers=self.headers,
                data={'hash': self.hash},
                timeout=20
            )
            resp = r.json() if r.content else {}
            if r.status_code != 200:
                return {'success': False, 'error': f'HTTP {r.status_code}: {resp}'}
            return {'success': True, 'response': resp}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_http_logs(self):
        print('  [*] Getting HTTP logs...')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/httptools',
                headers=self.headers,
                data={'hash': self.hash},
                timeout=20
            )
            data     = r.json()
            log_path = os.path.join(self.output_dir, 'logs', 'http_logs.json')
            with open(log_path, 'w', encoding='utf-8') as f:
                import json
                json.dump(data, f, indent=2)
            return {'success': True, 'data': data, 'path': log_path}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # -----------------------------------------
    # FRIDA
    # -----------------------------------------

    def get_frida_logs(self):
        print('  [*] Getting Frida logs...')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/frida_logs',
                headers=self.headers,
                data={'hash': self.hash},
                timeout=20
            )
            data     = r.json()
            log_path = os.path.join(
                self.output_dir, 'logs', 'frida_logs.json')
            with open(log_path, 'w', encoding='utf-8') as f:
                import json
                json.dump(data, f, indent=2)
            return {'success': True, 'data': data, 'path': log_path}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def run_frida_script(self, script_type='default'):
        """
        Run default Frida hooks via the MobSF instrument endpoint.
        Hooks: API Monitor, SSL Pinning Bypass, Root Bypass,
               Debugger Check Bypass, Clipboard Monitor.
        After injecting, waits 5s then auto-reads Frida logs.
        """
        print(f'  [*] Running Frida instrumentation: {script_type}')
        try:
            default_hooks = (
                'api_monitor,'
                'ssl_pinning_bypass,'
                'root_bypass,'
                'debugger_check_bypass,'
                'clipboard_monitor'
            )
            r = requests.post(
                f'{self.server}/api/v1/android/instrument',
                headers=self.headers,
                data={
                    'hash':          self.hash,
                    'default_hooks': default_hooks,
                    'auxiliary_hooks': ''
                },
                timeout=30
            )
            resp_data = r.json() if r.content else {}

            if r.status_code not in (200, 201):
                return {
                    'success': False,
                    'error':   f'HTTP {r.status_code}: {resp_data}'
                }

            # Wait for hooks to capture data, then read logs
            time.sleep(5)
            logs = self.get_frida_logs()

            return {
                'success':  True,
                'response': resp_data,
                'logs':     logs.get('data', {})
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def run_named_frida_script(self, script_name):
        """
        Run a specific named Frida script from MobSF's library.
        Available: crypto-aes-key, crypto-trace-cipher, audit-webview,
                   crypto-dump-keystore, bypass-emulator-detection, etc.
        """
        print(f'  [*] Running named Frida script: {script_name}')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/instrument',
                headers=self.headers,
                data={
                    'hash':            self.hash,
                    'default_hooks':   '',
                    'auxiliary_hooks': script_name
                },
                timeout=30
            )
            resp_data = r.json() if r.content else {}

            if r.status_code not in (200, 201):
                return {
                    'success': False,
                    'error':   f'HTTP {r.status_code}: {resp_data}'
                }

            time.sleep(5)
            logs = self.get_frida_logs()

            return {
                'success':  True,
                'response': resp_data,
                'logs':     logs.get('data', {})
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # -----------------------------------------
    # LOGCAT
    # -----------------------------------------

    def get_logcat(self):
        print('  [*] Getting logcat...')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/logcat',
                headers=self.headers,
                data={'hash': self.hash},
                timeout=20
            )
            data     = r.json()
            log_path = os.path.join(
                self.output_dir, 'logs', 'logcat.json')
            with open(log_path, 'w', encoding='utf-8') as f:
                import json
                json.dump(data, f, indent=2)
            return {'success': True, 'data': data, 'path': log_path}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # -----------------------------------------
    # EXPORTED COMPONENTS
    # -----------------------------------------

    def test_exported_activities(self):
        """
        Test all exported activities via MobSF's exported activity tester,
        with an ADB fallback to enumerate them directly.
        """
        print('  [*] Testing exported activities...')
        results = []

        # Step 1: get activity list from MobSF
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/activity',
                headers=self.headers,
                data={'hash': self.hash},
                timeout=30
            )
            if r.status_code == 200:
                activity_data = r.json()
                activities    = activity_data.get('activities', [])
                print(f'  [*] Found {len(activities)} activities via MobSF')
                results.append({'source': 'mobsf', 'data': activity_data})
            else:
                print(f'  [WARN] MobSF activity endpoint returned HTTP {r.status_code}')
        except Exception as e:
            print(f'  [WARN] MobSF activity endpoint failed: {e}')

        # Step 2: ADB fallback — enumerate exported activities directly
        try:
            adb_result = subprocess.run(
                ['adb', 'shell', 'dumpsys', 'package', self._package_name or ''],
                timeout=15, capture_output=True, text=True
            )
            if adb_result.returncode == 0:
                output = adb_result.stdout
                # Parse exported activities from dumpsys
                exported = []
                for line in output.splitlines():
                    line = line.strip()
                    if 'Activity' in line and 'exported=true' in line:
                        exported.append(line)
                    elif line.startswith('android.intent.action.MAIN'):
                        exported.append(line)
                results.append({'source': 'adb_dumpsys', 'exported_activities': exported})
                print(f'  [*] ADB found {len(exported)} exported activities')
        except Exception as e:
            print(f'  [WARN] ADB exported activity check failed: {e}')

        if results:
            return {'success': True, 'data': results}
        return {'success': False, 'error': 'All exported activity checks failed'}

    # -----------------------------------------
    # TOOL LIST FOR AI
    # -----------------------------------------

    def get_tool_list(self):
        return {
            'start_activity':           'Launch specific app activity by its full class name',
            'launch_app':               'Launch app from home screen via adb monkey',
            'stop_app':                 'Force stop the app',
            'adb_input_text':           'Type text into the focused input field',
            'adb_tap':                  'Tap on screen at x,y coordinates',
            'adb_press_key':            'Press Android key (66=Enter, 4=Back, 3=Home)',
            'take_screenshot':          'Capture emulator screenshot',
            'start_pcap':               'Start network packet capture (call before exercising app)',
            'stop_pcap':                'Stop network packet capture',
            'get_http_logs':            'Get all captured HTTP/HTTPS traffic (call after stop_pcap)',
            'get_frida_logs':           'Get Frida runtime hook logs (call after run_frida_script)',
            'run_frida_script':         'Inject default Frida hooks: API monitor, SSL bypass, root bypass, debugger bypass, clipboard monitor',
            'run_named_frida_script':   'Run a specific Frida script by name (e.g. crypto-aes-key, audit-webview, crypto-trace-cipher)',
            'get_logcat':               'Get Android system logs (useful for crash info, debug output, data leakage)',
            'test_exported_activities': 'Enumerate and test all exported app activities',
        }