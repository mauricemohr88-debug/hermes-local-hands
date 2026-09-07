# Running Hermes Local Hands as a user service

The service must remain bound to a loopback address. A private tunnel or reverse
proxy can forward HTTPS to it, but only exact proxy host names supplied through
`--proxy-host` are accepted.

## macOS LaunchAgent

Install the package in a stable, isolated location first:

```bash
uv tool install hermes-local-hands
command -v hermes-local-hands
```

Create `~/Library/LaunchAgents/com.example.hermes-local-hands.plist` with the
absolute executable and state paths returned on your machine:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.hermes-local-hands</string>
  <key>ProgramArguments</key>
  <array>
    <string>/absolute/path/to/hermes-local-hands</string>
    <string>--state-dir</string>
    <string>/Users/you/.local/state/hermes-local-hands</string>
    <string>serve</string>
    <string>--host</string>
    <string>127.0.0.1</string>
    <string>--port</string>
    <string>8741</string>
    <string>--proxy-host</string>
    <string>your-mac.example.ts.net</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ProcessType</key>
  <string>Background</string>
  <key>Umask</key>
  <integer>63</integer>
  <key>StandardOutPath</key>
  <string>/Users/you/Library/Logs/hermes-local-hands.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/you/Library/Logs/hermes-local-hands.error.log</string>
</dict>
</plist>
```

Load it for the current logged-in user:

```bash
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/com.example.hermes-local-hands.plist
launchctl print "gui/$(id -u)/com.example.hermes-local-hands"
```

Do not place the bearer credential in the plist. It belongs only in the remote
Hermes process's private environment.

## Linux user unit

Create `~/.config/systemd/user/hermes-local-hands.service`:

```ini
[Unit]
Description=Hermes Local Hands
After=network.target

[Service]
Type=simple
ExecStart=/absolute/path/to/hermes-local-hands --state-dir /home/you/.local/state/hermes-local-hands serve --host 127.0.0.1 --port 8741 --proxy-host your-host.example.net
Restart=on-failure
RestartSec=3
UMask=0077

[Install]
WantedBy=default.target
```

Then run:

```bash
systemctl --user daemon-reload
systemctl --user enable --now hermes-local-hands.service
systemctl --user status hermes-local-hands.service
```

## Smoke checks

An unauthenticated request must be rejected:

```bash
curl --silent --output /dev/null --write-out '%{http_code}\n' http://127.0.0.1:8741/mcp
# Expected: 401
```

Verify the retained receipt chain locally:

```bash
hermes-local-hands receipt-verify
```

Service startup, tunnel reachability, and receipt verification are separate
checks. A running process does not prove the tunnel or a remote Hermes client is
configured correctly.
