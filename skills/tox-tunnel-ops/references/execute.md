# Execute Reference

Use this reference when the user wants to deploy a ToxTunnel setup, install the
binary, start processes, or configure service persistence.

## Step 0: Environment Detection

Run these checks before writing files or starting anything:

### 1. Is `toxtunnel` installed?

```bash
which toxtunnel 2>/dev/null || where toxtunnel 2>nul
```

If not found, prefer package installation over source builds.

#### One-line install (recommended)

The repo ships installer scripts that auto-detect arch, download the matching
native package from GitHub Releases, install it, and seed `config.yaml`
based on `--mode`. Client mode writes a config scaffold and leaves the system
service idled (exit 0) until the user fills in `client.server_id` and sets
`service.allow_client_daemon: true`.

```bash
# macOS / Linux (DEB / RPM / .pkg auto-detected)
curl -fsSL https://raw.githubusercontent.com/anonymoussoft/tox-tcp-tunnel/master/scripts/install.sh | sudo sh                       # server
curl -fsSL https://raw.githubusercontent.com/anonymoussoft/tox-tcp-tunnel/master/scripts/install.sh | sudo sh -s -- --mode client   # client scaffold
```

```powershell
# Windows (Administrator PowerShell)
irm https://raw.githubusercontent.com/anonymoussoft/tox-tcp-tunnel/master/scripts/install.ps1 | iex                                       # server
$env:TOXTUNNEL_MODE='client'; irm https://raw.githubusercontent.com/anonymoussoft/tox-tcp-tunnel/master/scripts/install.ps1 | iex         # client scaffold
```

Env vars / flags: `TOXTUNNEL_MODE`, `TOXTUNNEL_VERSION`, `TOXTUNNEL_REPO`. The
installer is idempotent on the same mode and refuses to overwrite a
user-customized config (only rewrites the freshly seeded server template
when switching to client).

#### Manual install per platform

Each release also publishes both versioned assets
(`toxtunnel-<VERSION>-<System>-<arch>.<ext>`) and a stable `-latest` alias
(`toxtunnel-<System>-<arch>-latest.<ext>`). Use the alias URLs below for the
newest release.

#### Linux (DEB - Ubuntu/Debian)

```bash
ARCH=x86_64      # or aarch64
wget "https://github.com/anonymoussoft/tox-tcp-tunnel/releases/latest/download/toxtunnel-Linux-${ARCH}-latest.deb"
sudo dpkg -i "toxtunnel-Linux-${ARCH}-latest.deb"
```

#### Linux (RPM - Fedora/RHEL/CentOS)

```bash
ARCH=x86_64      # or aarch64
wget "https://github.com/anonymoussoft/tox-tcp-tunnel/releases/latest/download/toxtunnel-Linux-${ARCH}-latest.rpm"
sudo rpm -i "toxtunnel-Linux-${ARCH}-latest.rpm"
```

#### macOS

```bash
ARCH=arm64       # or x86_64
wget "https://github.com/anonymoussoft/tox-tcp-tunnel/releases/latest/download/toxtunnel-Darwin-${ARCH}-latest.pkg"
sudo installer -pkg "toxtunnel-Darwin-${ARCH}-latest.pkg" -target /
```

#### Windows

Download the MSI from
`https://github.com/anonymoussoft/tox-tcp-tunnel/releases/latest/download/toxtunnel-Windows-AMD64-latest.msi`
(use `toxtunnel-Windows-ARM64-latest.msi` for ARM) and run it as Administrator.

#### Build from source (only if no package fits)

- macOS: `brew install libsodium && cd <project> && cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j$(sysctl -n hw.ncpu) && sudo cp build/toxtunnel /usr/local/bin/`
- Linux (Debian/Ubuntu): `sudo apt install libsodium-dev build-essential cmake && cd <project> && cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j$(nproc) && sudo cp build/toxtunnel /usr/local/bin/`
- Linux (Fedora/RHEL): `sudo dnf install libsodium-devel cmake gcc-c++ && ...`
- Windows: build with MSVC + vcpkg or MSYS2 (see `BUILDING.md`)

### 2. Is libsodium available?

```bash
pkg-config --exists libsodium && echo "OK" || echo "MISSING"
# or: ldconfig -p | grep libsodium   (Linux)
# or: brew list libsodium            (macOS)
```

### 3. Are target ports available?

```bash
lsof -i :PORT -sTCP:LISTEN    # macOS/Linux
netstat -an | findstr :PORT   # Windows
```

### 4. Detect OS for path and service defaults

- macOS (from `.pkg`): `binary: /usr/local/bin/toxtunnel`, example config at `/usr/local/share/toxtunnel/config.yaml.example`. The pkg postinstall automatically seeds `/usr/local/etc/toxtunnel/config.yaml` (from the example), installs `com.toxtunnel.daemon.plist` into `/Library/LaunchDaemons/`, and runs `launchctl bootstrap`.
- macOS (manual/source build): `data_dir: ~/Library/Application Support/toxtunnel/` or `~/.config/toxtunnel/`, service: launchd user agent
- Linux (from DEB/RPM): `binary: /usr/bin/toxtunnel`, `config: /etc/toxtunnel/config.yaml`, `data_dir: /var/lib/toxtunnel`, service: `toxtunnel.service` (Type=notify, `RemainAfterExit=yes`, enabled and started by postinst).
- Linux (manual): `data_dir: ~/.config/toxtunnel/`, service: custom systemd unit
- Windows (from MSI): `binary: C:\Program Files\ToxTunnel\bin\toxtunnel.exe`. The MSI registers the **ToxTunnel** SCM service (Start="install", auto) pointing at `C:\ProgramData\ToxTunnel\config.yaml`. The MSI does NOT seed `config.yaml` itself; the daemon's `--service` soft-fail path lets first-boot exit 0 cleanly until the user creates one. `scripts/install.ps1` does seed it based on `--Mode`.
- Windows (manual): `data_dir: %APPDATA%\toxtunnel\`, service: NSSM or Task Scheduler

## Step 1: Write Config Files

Generate and write:

- `server.yaml`
- `client.yaml`
- `rules.yaml` when access control is needed

Use the templates under `templates/` and enforce the minimum-privilege rules from
the main skill.

## Step 2: Startup Commands

```bash
# Server side
toxtunnel -m server -c /path/to/server.yaml

# Client side
toxtunnel -m client -c /path/to/client.yaml
```

If running on the current machine, only start processes after explicit user request.

## Step 3: Service Persistence

Only do this when the user explicitly asks for persistent service management.

### Linux DEB/RPM

Postinst creates the `toxtunnel` system user, seeds `/etc/toxtunnel/config.yaml`
from the example if missing, registers `toxtunnel.service`, and runs
`systemctl enable --now`. The unit is `Type=notify` with `RemainAfterExit=yes`,
so a daemon that gates itself off (client mode without `allow_client_daemon`,
or missing config under `--service`) shows as `active (exited)` rather than
`inactive (dead)`.

```bash
sudo vim /etc/toxtunnel/config.yaml      # already seeded; edit in place
sudo systemctl restart toxtunnel         # apply changes
sudo systemctl status toxtunnel
```

### macOS `.pkg`

The pkg postinstall (`packaging/macos/postinstall.sh`) seeds
`/usr/local/etc/toxtunnel/config.yaml` from the example if missing, installs
`com.toxtunnel.daemon.plist` into `/Library/LaunchDaemons/`, and runs
`launchctl bootstrap system`. The plist's `KeepAlive { SuccessfulExit: false }`
means a config-gated exit-0 daemon stays stopped (won't loop). On newer macOS
versions, `launchctl bootstrap` may require user approval in System Settings →
Privacy & Security; the postinstall treats that failure as non-fatal.

```bash
sudo vim /usr/local/etc/toxtunnel/config.yaml          # already seeded; edit in place
sudo launchctl kickstart -k system/com.toxtunnel.daemon  # apply changes
sudo launchctl print system/com.toxtunnel.daemon | head
```

### Windows MSI

The MSI registers the **ToxTunnel** Windows SCM service automatically
(`ServiceInstall` Type=ownProcess, Start=auto; `ServiceControl Start="install"`)
pointing at `C:\Program Files\ToxTunnel\bin\toxtunnel.exe -c
C:\ProgramData\ToxTunnel\config.yaml --service`. The MSI does NOT seed the
config — the daemon's `--service` soft-fail path makes first boot exit 0 cleanly
so SCM marks the service stopped (not failed). The user creates the YAML, then
starts the service:

```powershell
mkdir 'C:\ProgramData\ToxTunnel' -Force
notepad 'C:\ProgramData\ToxTunnel\config.yaml'
sc start ToxTunnel
sc query ToxTunnel
sc stop ToxTunnel
```

### Manual source-build service templates

#### Linux systemd

```ini
[Unit]
Description=ToxTunnel %i
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/toxtunnel -m %i -c /etc/toxtunnel/%i.yaml --service
Restart=on-failure
RestartSec=5
User=toxtunnel
WorkingDirectory=/etc/toxtunnel

[Install]
WantedBy=multi-user.target
```

Install with:
`sudo cp toxtunnel@.service /etc/systemd/system/ && sudo systemctl enable --now toxtunnel@server`

#### macOS launchd

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.toxtunnel.MODE</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/toxtunnel</string>
        <string>-m</string>
        <string>MODE</string>
        <string>-c</string>
        <string>/usr/local/etc/toxtunnel/MODE.yaml</string>
        <string>--service</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/usr/local/var/log/toxtunnel-MODE.log</string>
    <key>StandardErrorPath</key>
    <string>/usr/local/var/log/toxtunnel-MODE.log</string>
</dict>
</plist>
```

Install with:
`cp com.toxtunnel.MODE.plist ~/Library/LaunchAgents/ && launchctl load ~/Library/LaunchAgents/com.toxtunnel.MODE.plist`

#### Windows `sc.exe`

```cmd
sc create ToxTunnel binPath= "\"C:\path\to\toxtunnel.exe\" -c \"C:\path\to\config.yaml\" --service" start= auto
sc start ToxTunnel
```

#### Windows NSSM

```cmd
nssm install ToxTunnel-MODE "C:\path\to\toxtunnel.exe" -m MODE -c "C:\path\to\MODE.yaml"
nssm set ToxTunnel-MODE AppStdout "C:\path\to\logs\MODE.log"
nssm set ToxTunnel-MODE AppStderr "C:\path\to\logs\MODE.log"
nssm start ToxTunnel-MODE
```

## Step 4: Lifecycle Operations

### Start / Stop / Restart

```bash
# Direct process
toxtunnel -m server -c server.yaml &
kill $(pgrep -f "toxtunnel.*server")

# systemd
sudo systemctl start toxtunnel
sudo systemctl stop toxtunnel
sudo systemctl restart toxtunnel
sudo systemctl start toxtunnel@server
sudo systemctl stop toxtunnel@server

# launchd
sudo launchctl bootstrap system /Library/LaunchDaemons/com.toxtunnel.daemon.plist
sudo launchctl bootout system /Library/LaunchDaemons/com.toxtunnel.daemon.plist
launchctl start com.toxtunnel.server
launchctl stop com.toxtunnel.server

# Windows SCM
sc start ToxTunnel
sc stop ToxTunnel

# Windows NSSM
nssm start ToxTunnel-server
nssm stop ToxTunnel-server
```

### View logs

```bash
tail -f /var/log/toxtunnel/server.log
journalctl -u toxtunnel@server -f
tail -f /usr/local/var/log/toxtunnel-server.log
toxtunnel -m server -c server.yaml -l debug
```

## Step 4.5: Known-Servers Registry (client side)

After a successful client→server connection, the client persists an entry in
`<data_dir>/known_servers.yaml`. Manage it from the CLI:

```bash
toxtunnel servers list                       # compact list of saved servers
toxtunnel servers list --full                # show full 76-char Tox IDs
toxtunnel servers show <alias_or_tox_id>     # full record incl. info disclosed by server
toxtunnel servers add  <alias> <tox_id>      # name a Tox ID
toxtunnel servers remove <alias_or_tox_id>   # forget
```

After `servers add homelab DE47F2...`, both `--server-id homelab` and
`client.server_id: homelab` resolve from the registry at startup.

For server-side info disclosure (defaults to nothing), uncomment the relevant
fields under `server.disclose:` in `server.yaml`:

```yaml
server:
  rules_file: rules.yaml
  disclose:
    hostname: true
    os: true
    arch: true
```

The disclosed snapshot is sent via `INFO_REPLY` (frame 0x07) when the client
sends an `INFO_REQUEST` (frame 0x06) on first reaching online state.

## Step 5: Post-Deploy Verification

```bash
bash scripts/verify.sh <local_port> <service_type>
```

## Output Format

```text
## Environment Check
- toxtunnel: [installed at /usr/local/bin/toxtunnel | NOT FOUND]
- libsodium: [OK | MISSING]
- Port XXXX: [available | in use by PROCESS]
- OS: [macOS / Linux / Windows]

## Generated Files
- server.yaml -> /path/to/server.yaml
- client.yaml -> /path/to/client.yaml
- rules.yaml  -> /path/to/rules.yaml  (if applicable)

## Startup Commands
[OS-specific commands]

## Service Persistence
[Only if requested: systemd/launchd/NSSM config]

## Lifecycle Commands
[start / stop / restart / logs]

## Verification
[Test command and expected output]
```
