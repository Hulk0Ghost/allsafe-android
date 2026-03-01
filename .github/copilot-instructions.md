# Allsafe Android - AI Coding Agent Instructions

**Project**: An intentionally vulnerable Android app for security education with 20+ challenges demonstrating real-world vulnerabilities.

## Architecture Overview

**Navigation-based Fragment architecture** with a single-module app structure:
- **MainActivity** (`MainActivity.kt`): Hosts a DrawerLayout navigation drawer with 20+ challenge destinations
- **Navigation Graph** (`res/navigation/`): Defines all challenge fragments accessible via navigation drawer
- **Challenges** (`app/src/main/java/.../challenges/`): Individual vulnerability implementations (mixed Java/Kotlin)
- **ArbitraryCodeExecution.kt**: Custom Application class for instrumentation hooks

### Key Navigation Destinations
Challenges are registered in `MainActivity.kt` with navigation IDs (e.g., `nav_insecure_logging`, `nav_sql_injection`). Each maps to either a Fragment or custom Activity. The NavigationUI framework handles drawer-to-fragment transitions.

### Challenge Pattern
Challenges are primarily Fragment subclasses that:
1. Inflate a challenge-specific layout from `res/layout/fragment_*.xml`
2. Initialize vulnerable components (WebView, Services, Broadcast Receivers, SQLite)
3. Use `SnackUtil.simpleMessage()` for user feedback
4. May execute async HTTP calls via OkHttp3 (`client.newCall(req).enqueue()`)

**Examples**: `InsecureLogging.java` logs secrets to logcat; `VulnerableWebView.java` enables JavaScript and file access; `HardcodedCredentials.kt` embeds SOAP credentials.

## Critical Workflows

### Building & Installation
```bash
# Debug APK (default for development)
./gradlew assembleDebug

# Install to device/emulator
adb install app/build/outputs/apk/debug/app-debug.apk

# Direct logcat monitoring for debugging
adb shell logcat | grep ALLSAFE
```

### Release Build
```bash
./gradlew assembleRelease  # Currently disables minification (minifyEnabled=false)
```

### CI/CD (Jenkins Pipeline)
Jenkinsfile validates APKs and uploads to **MobSF** (Mobile Security Framework) for automated security scanning. Triggered on commits.

## Project-Specific Conventions

### Language Mix
- **Kotlin** preference for new fragments (e.g., `HardcodedCredentials.kt`, `NativeLibrary.kt`)
- **Java** retained for legacy challenges and utility classes
- Both are compiled to Java 18 bytecode

### Package Structure
```
infosecadventures.allsafe/
├── MainActivity, MainFragment, ProxyActivity (core navigation)
├── ChallengeAdapter, ChallengeItem (metadata model)
├── challenges/ (20+ vulnerability implementations)
├── utils/ (SnackUtil, ClipUtil)
└── ArbitraryCodeExecution (Application class)
```

### Naming Convention for Challenges
Challenge classes match their vulnerability type (e.g., `InsecureLogging.java`, `SQLInjection.kt`, `VulnerableWebView.java`) and appear in the drawer menu.

## Integration Points & Dependencies

### Firebase Integration
- **Realtime Database** (`firebase-database-ktx:21.0.0`): Used in `FirebaseDatabase.kt` challenge
- **Cloud Storage** (`firebase-storage-ktx:21.0.1`): For file upload challenges
- **Configuration**: `google-services.json` required; auto-downloaded by Gradle plugin

### Native Code
- **CMake** (`src/main/cpp/CMakeLists.txt`): C++ challenge (`NativeLibrary.kt`)
- **NDK v25.1.8937393**: Configured for native compilation

### Key External Libraries
- **OkHttp3** (4.9.0): HTTP client for `HardcodedCredentials` and credential exfiltration demos
- **AndroidSecurity** (1.1.0-alpha06): Encryption demos
- **RootBeer** (0.0.8): Root detection check in `RootDetection.kt`
- **Material Design** (1.12.0): Navigation drawer, text inputs, buttons

### Permissions (AndroidManifest.xml)
Notable permissions: `INTERNET`, `RECORD_AUDIO`, `READ/WRITE_EXTERNAL_STORAGE`, `QUERY_ALL_PACKAGES`. App is explicitly debuggable (`android:debuggable="true"`).

## Architectural Decisions & Why

1. **Fragment-based over Activity-heavy**: Enables lightweight challenge transitions via Navigation component
2. **Mixed Java/Kotlin**: Java retained for legacy challenges to demonstrate multi-language real-world apps
3. **Intentional Vulnerabilities**: Each challenge leaves security gaps deliberately to teach exploitation techniques
4. **FLAG_SECURE window**: Set in `MainActivity.onCreate()` for screenshot prevention in some contexts
5. **Custom Application class**: `ArbitraryCodeExecution` enables instrumentation testing for dynamic challenge validation
6. **Drawer Navigation**: Centralizes challenge discovery in a user-friendly menu rather than tabbed UI

## Common Development Tasks

### Adding a New Challenge
1. Create Fragment/Activity in `challenges/` directory
2. Create layout file in `res/layout/fragment_*.xml`
3. Add Navigation destination in `res/navigation/nav_graph.xml` with unique ID
4. Register navigation ID in `MainActivity.kt` `AppBarConfiguration.Builder`
5. Add menu item reference if needed in `res/menu/`

### Debugging
- Use `adb logcat` to monitor all app output (filter by `ALLSAFE` tag)
- Attach debugger via Android Studio for breakpoints
- Check `lint-baseline.xml` for suppressed lint warnings

### Testing Integration
MobSF pipeline runs automatically; APK must exist at `samples/allsafe.apk` for CI to pass. Pre-built samples available in releases.

## Build Configuration Highlights

- **compileSdkVersion**: 35 (latest APIs)
- **minSdkVersion**: 23 (API 23+)
- **targetSdk**: 35
- **Java Target**: 18 (set via `jvmToolchain(18)`)
- **Lint**: Aborts on error; baseline stored in `lint-baseline.xml`
- **Proguard**: Configured but disabled in debug builds

## Notes for AI Agents

- This is **intentionally insecure code** designed for education—do NOT use patterns from this codebase in production apps
- Refer to layout files when modifying UI (fragments heavily depend on XML layouts)
- When adding challenges, maintain the existing Fragment lifecycle pattern
- Firebase operations are async; challenges often show UI feedback via SnackUtil before results complete
- Native library calls routed through `NativeLibrary.kt` JNI bindings
