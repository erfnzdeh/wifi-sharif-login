# wifi-sharif-login

Sign in to Sharif Wi-Fi from the command line.

```
net2
net2 status
net2 disconnect
```

Put `NET_SHARIF_USER` and `NET_SHARIF_PASSWORD` in `credentials.env`.

## Mac auto-connect

`wifi-watch` checks the Wi-Fi name every 10 seconds. On Sharif-WiFi it runs `net2`. A failed attempt is retried after 60 seconds. Output goes to `net2.log`.

```sh
ln -sfn "$PWD/login.py" ~/.local/bin/net2
```

Add the same path to `~/.zshrc`:

```sh
alias net2='/path/to/wifi-sharif-login/login.py'
```

Save this as `~/Library/LaunchAgents/local.net2.wifi.plist` (replace the repo path):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>local.net2.wifi</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/wifi-sharif-login/wifi-watch</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
    <key>StartInterval</key>
    <integer>10</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/path/to/wifi-sharif-login/net2.log</string>
    <key>StandardErrorPath</key>
    <string>/path/to/wifi-sharif-login/net2.log</string>
</dict>
</plist>
```

```sh
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/local.net2.wifi.plist
```
