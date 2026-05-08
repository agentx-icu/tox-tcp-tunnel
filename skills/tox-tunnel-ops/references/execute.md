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

Each release publishes both versioned assets
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

- macOS (from `.pkg`): `binary: /usr/local/bin/toxtunnel`, example config at `/usr/local/share/toxtunnel/config.yaml.example`, launchd plist at `/usr/local/share/toxtunnel/com.toxtunnel.daemon.plist`
- macOS (manual/source build): `data_dir: ~/Library/Application Support/toxtunnel/` or `~/.config/toxtunnel/`, service: launchd user agent
- Linux (from DEB/RPM): `binary: /usr/bin/toxtunnel`, `config: /etc/toxtunnel/config.yaml`, `data_dir: /var/lib/toxtunnel`, service: `toxtunnel.service`
- Linux (manual): `data_dir: ~/.config/toxtunnel/`, service: custom systemd unit
- Windows (from MSI): `binary: C:\Program Files\ToxTunnel\bin\toxtunnel.exe`; MSI does not seed config or register a service
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

Postinst registers and enables `toxtunnel.service`, seeds
`/etc/toxtunnel/config.yaml` if missing, and creates the `toxtunnel` user. The
service is enabled but not started by default.

```bash
sudo vim /etc/toxtunnel/config.yaml
sudo systemctl start toxtunnel
sudo systemctl enable toxtunnel
sudo systemctl status toxtunnel
```

### macOS `.pkg`

The package installs the binary, example config, and launchd plist, but does not
load the job automatically.

```bash
sudo mkdir -p /usr/local/etc/toxtunnel
sudo cp /usr/local/share/toxtunnel/config.yaml.example /usr/local/etc/toxtunnel/config.yaml
sudo vim /usr/local/etc/toxtunnel/config.yaml

sudo cp /usr/local/share/toxtunnel/com.toxtunnel.daemon.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/com.toxtunnel.daemon.plist
sudo launchctl bootout system /Library/LaunchDaemons/com.toxtunnel.daemon.plist
```

### Windows MSI

The MSI installs files only. Create the service manually after you place a config.

```powershell
sc create ToxTunnel binPath= "\"C:\Program Files\ToxTunnel\bin\toxtunnel.exe\" -c \"C:\ProgramData\ToxTunnel\config.yaml\" --service" start= auto
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
