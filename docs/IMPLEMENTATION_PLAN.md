# NetSpeed VPN — End-to-End Implementation Plan

## Project Overview

NetSpeed is a custom VPN system with:
- **Android client** (Kotlin) at `C:\Users\shive\AndroidStudioProjects\NetSpeedv3\`
- **C++ VPN server** (Cpp-VPN-Core) at `C:\Users\shive\Documents\GitHub\Cpp-VPN-Core\`
- **Terraform infrastructure** (GCP) at `C:\Users\shive\Documents\GitHub\vpn-infra\`

The app uses a custom UDP protocol (port 5555) with XOR cipher + Diffie-Hellman key exchange, a TUN device on both ends, and foreground services on Android.

---

## Current State Audit

### What is FULLY working end-to-end:
- VPN connect/disconnect with handshake (HELLO → WELCOME → CLIENT_ACK → DATA)
- PKT_BYE on disconnect (sent 3x for UDP reliability)
- Keepalive packets every 15s
- Foreground notification for VPN + speed monitoring (separate services, separate notification IDs: 200 and 100)
- Google Sign-In auth gate on VPN functionality
- Saved server list (SharedPreferences, shown in spinner on VPN page)
- Split tunneling — UI saves excluded apps to SharedPreferences, `MyVpnService.createTun()` reads them and calls `addDisallowedApplication()` per package
- Data usage tracking on Speed page — uses `TrafficStats.getTotalRxBytes()/getTotalTxBytes()` to show cumulative session usage
- Speed notification first-click bug fix — uses `pendingStart` flag + delayed confirmation instead of racing `isServiceRunning` flip
- Full UI redesign (Option B "Clean Trust" — light surfaces, teal accents, 4-tab nav)

### What has UI but NO backend logic:
1. **Kill switch** — toggle exists in `VpnSettingsFragment`, saves to `SharedPreferences` key `kill_switch`, but `MyVpnService` does NOT read it or implement any kill-switch behavior
2. **Auto-connect** — toggle exists, saves to key `auto_connect`, but nothing reads it on app launch
3. **Protocol selector** — shows "UDP (recommended)" as static text, no TCP option exists and the server only supports UDP anyway

### Server-side issues:
- `CLIENT_DEAD_TIMEOUT = 60` in `main.cpp` line 240 — too aggressive, causes IP reassignment after 1 minute of inactivity. Should be 300s.
- XOR cipher is placeholder — not secure for production

---

## Implementation Plan

### Phase 1: Complete Kill Switch (Android only)

**What it does:** When kill switch is ON and VPN drops unexpectedly, block all internet traffic until VPN reconnects.

**Files to modify:**
- `app/src/main/java/org/thinkSlow/netspeedv3/MyVpnService.kt`

**Implementation:**
1. In `createTun()`, read the kill switch preference:
```kotlin
val killSwitchEnabled = settingsPrefs.getBoolean(
    VpnSettingsFragment.KEY_KILL_SWITCH, false
)
```
2. If kill switch is ON, set `builder.setBlocking(true)` — this tells Android's VPN framework to block traffic when the VPN interface goes down
3. Additionally, add `builder.allowBypass(false)` when kill switch is ON to prevent apps from bypassing the VPN using `ConnectivityManager.bindProcessToNetwork()`
4. In `disconnectVpn()`, if the disconnect was NOT user-initiated (i.e., triggered by a network error in `vpnMainLoop`), DON'T close the TUN interface — leave it open so traffic stays blocked. Only close TUN on explicit user disconnect via `ACTION_STOP`.

**How to distinguish user disconnect vs crash:**
- Add a boolean `userInitiatedStop` flag
- Set it to `true` in `onStartCommand` when `action == ACTION_STOP`
- In the `finally` block of `vpnMainLoop`, check this flag before calling `disconnectVpn()`

**Testing:**
- Enable kill switch, connect VPN, then kill the server process on GCP
- Verify that the phone shows no internet (browser should fail to load pages)
- Open the app, tap Disconnect — internet should restore
- With kill switch OFF, repeat — internet should continue working even when VPN drops

---

### Phase 2: Complete Auto-Connect (Android only)

**What it does:** When the app opens, automatically connect to the last-used server.

**Files to modify:**
- `app/src/main/java/org/thinkSlow/netspeedv3/VPNFragment.kt`
- `app/src/main/java/org/thinkSlow/netspeedv3/MyVpnService.kt` (minor)

**Implementation:**
1. In `VPNFragment.onViewCreated()`, after `updateAuthState()` and `restoreVpnState()`:
```kotlin
// Auto-connect if enabled and not already connected
val settingsPrefs = requireContext().getSharedPreferences(
    VpnSettingsFragment.PREFS_NAME, Context.MODE_PRIVATE
)
val autoConnect = settingsPrefs.getBoolean(VpnSettingsFragment.KEY_AUTO_CONNECT, false)
if (autoConnect && !MyVpnService.isActive) {
    // Load last used server from prefs
    val lastServer = prefs.getString("last_server_ip", "") ?: ""
    if (lastServer.isNotBlank()) {
        serverIpInput.setText(lastServer)
        requestVpnPermission()
    }
}
```
2. In `startVpn()`, save the server IP as the last-used server:
```kotlin
requireContext().getSharedPreferences(ProfileFragment.PREFS_NAME, Context.MODE_PRIVATE)
    .edit().putString("last_server_ip", serverIp).apply()
```
3. Guard against auto-connect when the user isn't signed in (check `isUserSignedIn()` before auto-connecting)

**Testing:**
- Enable auto-connect, connect to a server, close app
- Reopen app — should auto-connect to same server
- Sign out, reopen — should NOT auto-connect (auth gate blocks it)
- With auto-connect OFF, reopen — should show normal disconnected state

---

### Phase 3: Fix Server CLIENT_DEAD_TIMEOUT

**File:** `Cpp-VPN-Core/main.cpp` line 240

**Change:**
```cpp
// Before
CLIENT_DEAD_TIMEOUT = 60;

// After
CLIENT_DEAD_TIMEOUT = 300;
```

**Why:** 60 seconds is too aggressive. The Android client sends keepalives every 15 seconds, so 300 seconds (5 minutes) gives plenty of buffer for temporary network drops (subway, elevator, Wi-Fi handoff) without sweeping the session.

**Testing:**
- Connect VPN, put phone in airplane mode for 2 minutes, then turn off airplane mode
- VPN should still work (same IP, same session) if keepalives resume within 5 minutes
- Wait 6 minutes in airplane mode — session should be swept, next connect gets a new IP

**Deployment:**
```bash
# From Cpp-VPN-Core directory
./build.ps1  # or the deploy script
# This builds the Docker image, extracts the binary, SCPs to GCP, and restarts
```

---

### Phase 4: Testing Strategy

#### 4A: Unit Tests (Android)

**Setup:** Add to `app/build.gradle.kts`:
```kotlin
testImplementation("junit:junit:4.13.2")
testImplementation("org.mockito:mockito-core:5.11.0")
testImplementation("org.mockito.kotlin:mockito-kotlin:5.2.1")
testImplementation("org.robolectric:robolectric:4.11.1")
```

**Test files to create in `app/src/test/java/org/thinkSlow/netspeedv3/`:**

1. **`PacketHeaderTest.kt`** — Test `PacketHeader.toByteArray()` and `fromByteArray()` round-trip, edge cases (session ID 0, max uint32, negative values)

2. **`EncryptionTest.kt`** — Test XOR encryption: encrypt then decrypt should return original bytes. Test with various key values including 0x00 and 0xFF.

3. **`HandshakeProtocolTest.kt`** — Test `modExp()` function with known DH values. Test `xorKeyFromSecret()` produces expected keys.

4. **`MssClampingTest.kt`** — Test `clampTcpMssIncremental()`:
   - SYN packet with MSS > clamp → should be clamped, checksum updated
   - SYN packet with MSS < clamp → should be untouched
   - Non-SYN packet → should be untouched
   - Non-TCP packet → should be untouched
   - Packet too short → should be untouched

5. **`ChecksumTest.kt`** — Test `checksum()` and `updateChecksumIncremental()` against known valid IP/TCP headers

6. **`SpeedFragmentLogicTest.kt`** — Test `formatBytes()` function: 0 → "0 B", 1500 → "1.5 KB", 1500000 → "1.5 MB", 1500000000 → "1.50 GB"

7. **`VpnSettingsTest.kt`** — Test that excluded apps are saved/loaded correctly from SharedPreferences (use Robolectric)

#### 4B: Instrumented Tests (Android)

**Setup:** Add to `app/build.gradle.kts`:
```kotlin
androidTestImplementation("androidx.test.ext:junit:1.1.5")
androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
androidTestImplementation("androidx.test:runner:1.5.2")
```

**Test files in `app/src/androidTest/java/org/thinkSlow/netspeedv3/`:**

1. **`MainActivityNavigationTest.kt`** — Test 4-tab navigation: clicking each tab shows the correct fragment

2. **`VpnSettingsUITest.kt`** — Test split tunneling toggle shows/hides the app list. Test adding and removing excluded apps.

3. **`SpeedFragmentUITest.kt`** — Test that the toggle button text changes between "Start Notification" and "Stop Notification"

#### 4C: Server Tests (C++)

**Create `Cpp-VPN-Core/tests/` directory:**

1. **`test_client_manager.cpp`** — Test IP pool allocation:
   - First client gets 10.8.0.2
   - Second client gets 10.8.0.3
   - After first client disconnects, next client gets 10.8.0.2 again
   - Pool exhaustion at 100 clients

2. **`test_handshake.cpp`** — Test handshake state machine:
   - Valid HELLO → WELCOME response with assigned IP
   - Duplicate HELLO from same source → same session
   - PKT_BYE → session removed
   - PKT_KEEPALIVE → lastSeen updated

3. **`test_sweep.cpp`** — Test dead client sweep:
   - Client with lastSeen > CLIENT_DEAD_TIMEOUT → removed
   - Client with recent lastSeen → kept
   - After sweep, IP is returned to pool

**Build system:** Add a simple Makefile target or CMake test target. Use a lightweight C++ test framework (Catch2 single-header or just assert macros).

#### 4D: Manual Test Checklist

Run this before every release:

```
[ ] Fresh install on Android 13+ device — notification permission prompt appears
[ ] Sign in with Google — profile shows name/email/badge
[ ] Add server IP on Profile page — appears in saved list
[ ] VPN page — server spinner shows saved servers
[ ] Connect VPN — ring turns green, shield icon, "Connected to [IP]" banner
[ ] Speed page — download/upload numbers update in real-time while VPN is on
[ ] Data usage — total/down/up counters increment, progress bar moves
[ ] Speed notification — start notification, verify it shows in status bar
[ ] Speed notification first click — works immediately (no need for stop/start)
[ ] VPN Settings — split tunneling toggle shows app list
[ ] Split tunneling — exclude Chrome, connect VPN, verify Chrome traffic bypasses VPN (check whatismyip.com in Chrome vs another browser)
[ ] Kill switch — enable, connect VPN, kill server, verify no internet
[ ] Auto-connect — enable, connect to server, force-close app, reopen, verify auto-connects
[ ] Dark mode — toggle in Profile, verify all screens adapt properly
[ ] Disconnect VPN — ring goes gray, banner disappears, stats hide
[ ] Sign out — returns to signed-out state, VPN page shows auth gate
[ ] Background/foreground — leave app for 5 minutes, return, state should be preserved
[ ] Notification swipe — swiping speed notification stops the service
[ ] VPN notification — shows "VPN is running", tapping opens app
```

---

### Phase 5: Code Quality & CI/CD

#### 5A: Add Lint and Static Analysis

**Add to `app/build.gradle.kts`:**
```kotlin
android {
    lint {
        abortOnError = true
        warningsAsErrors = false
        checkDependencies = true
    }
}
```

Run: `./gradlew lint` — fix any errors before proceeding.

#### 5B: GitHub Actions CI for Android

**Create `.github/workflows/android.yml` in the NetSpeedv3 repo:**

```yaml
name: Android CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with:
          java-version: '17'
          distribution: 'temurin'
      - name: Build
        run: ./gradlew assembleDebug
      - name: Unit Tests
        run: ./gradlew testDebugUnitTest
      - name: Lint
        run: ./gradlew lint
      - name: Upload APK
        uses: actions/upload-artifact@v4
        with:
          name: debug-apk
          path: app/build/outputs/apk/debug/app-debug.apk
```

#### 5C: GitHub Actions CI for Cpp-VPN-Core

**Create `.github/workflows/server.yml` in the Cpp-VPN-Core repo:**

```yaml
name: Server CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build Docker image
        run: docker build -t vpn-server .
      - name: Run tests
        run: docker run --rm vpn-server /app/run_tests  # if test binary exists
```

---

### Phase 6: Security Hardening (Future)

These are NOT blocking for launch but should be on the roadmap:

1. **Replace XOR cipher with AES-256-GCM** — The current XOR cipher is trivially breakable. Use OpenSSL's EVP API on the server and `javax.crypto.Cipher` on Android. The DH key exchange already produces a shared secret — derive a proper AES key from it using HKDF.

2. **Replace toy DH with proper ECDH** — Current DH uses P=127, G=9 which has only ~126 possible shared secrets. Use Curve25519 (libsodium on server, Tink or BouncyCastle on Android).

3. **Add server certificate pinning** — Prevent MITM during handshake by having the client verify the server's identity.

4. **Add replay protection** — Include a sequence number in each DATA packet to prevent replay attacks.

5. **Rate limit handshakes** — Prevent DDoS on the server by limiting HELLO packets per source IP.

---

### Phase 7: Production Readiness (Future)

1. **Crash reporting** — Add Firebase Crashlytics to the Android app
2. **Analytics** — Track connection success rate, average session duration, most-used servers
3. **Multiple servers** — Add a server list API endpoint, let users pick by region/latency
4. **App signing** — Set up Play Store signing key, create release build variant
5. **ProGuard/R8** — Enable code shrinking for release builds
6. **Upgrade GCP instance** — e2-micro is free tier but has limited bandwidth; consider e2-small for production

---

## Architecture Reference

### Android App Structure
```
app/src/main/java/org/thinkSlow/netspeedv3/
├── MainActivity.kt          — 4-tab nav (VPN, Speed, Settings, Profile)
├── VPNFragment.kt            — Connect ring, server input, status banner, session info
├── SpeedFragment.kt          — Speed cards, data usage, notification toggle
├── VpnSettingsFragment.kt    — Split tunneling, kill switch, auto-connect, protocol
├── ProfileFragment.kt        — Google Sign-In, saved servers, theme toggle
├── MyVpnService.kt           — VPN service (handshake, TUN, uplink/downlink/keepalive threads)
└── NetworkSpeedService.kt    — Speed monitoring foreground service (TrafficStats)
```

### Protocol Packet Types
| Type | Byte | Direction | Purpose |
|------|------|-----------|---------|
| PKT_HELLO | 1 | Client → Server | Initiate handshake (carries client_magic + DH public) |
| PKT_WELCOME | 2 | Server → Client | Assign IP (carries assigned_ip + DH public) |
| PKT_CLIENT_ACK | 3 | Client → Server | Acknowledge session |
| PKT_DATA | 4 | Both | Encrypted IP packet payload |
| PKT_BYE | 5 | Client → Server | Graceful disconnect (sent 3x) |
| PKT_KEEPALIVE | 6 | Client → Server | Prevent session timeout (every 15s) |

### Key SharedPreferences
| Prefs File | Key | Type | Used By |
|------------|-----|------|---------|
| `netspeed_prefs` | `saved_servers` | String (CSV) | ProfileFragment, VPNFragment |
| `netspeed_prefs` | `dark_theme` | Boolean | ProfileFragment |
| `netspeed_prefs` | `auto_speed_notif` | Boolean | ProfileFragment |
| `vpn_settings_prefs` | `split_tunnel_enabled` | Boolean | VpnSettingsFragment, MyVpnService |
| `vpn_settings_prefs` | `excluded_apps` | StringSet | VpnSettingsFragment, MyVpnService |
| `vpn_settings_prefs` | `kill_switch` | Boolean | VpnSettingsFragment, MyVpnService (TODO) |
| `vpn_settings_prefs` | `auto_connect` | Boolean | VpnSettingsFragment, VPNFragment (TODO) |

### Server (C++) Key Files
```
Cpp-VPN-Core/
├── main.cpp                          — Entry point, socket loop, CLIENT_DEAD_TIMEOUT
├── sessions/client/Client_Manager.cpp — IP pool (10.8.0.2+), session CRUD, sweepDeadClients()
├── sessions/client/Client_Manager.h   — ClientManager class definition
├── Dockerfile                         — Multi-stage build for cross-compilation
└── build.ps1                          — Build + deploy script (Docker → SCP → SSH restart)
```

### GCP Infrastructure
- Instance: `e2-micro` (free tier), zone `us-central1-a`
- Static IP: `35.193.111.181`
- Firewall: UDP port 5555 open
- Terraform state: local (in vpn-infra repo)

---

## Execution Order

For another Claude session, execute in this order:

1. **Phase 1** (Kill switch) — ~30 min, Android only
2. **Phase 2** (Auto-connect) — ~20 min, Android only
3. **Phase 3** (Server timeout fix) — ~5 min, requires server redeploy
4. **Phase 4A** (Unit tests) — ~1 hour, create test files
5. **Phase 4B** (Instrumented tests) — ~45 min, requires emulator context
6. **Phase 4D** (Manual test checklist) — user runs this themselves
7. **Phase 5** (CI/CD) — ~30 min, GitHub Actions setup

Phases 6 and 7 are future work and should be separate sessions.
