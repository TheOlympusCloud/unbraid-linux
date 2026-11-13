# Privacy

unbraid for Linux collects nothing for us. It has no analytics, advertising, crash reports or account, and it sends
nothing to this project or to Quiet Crafts, who made the Android app it is based on. This page lists everything the app
connects to, and why.

## On your computer

- Your setup and provider logins are kept in `~/.local/share/unbraid`, which only you can open, sealed with a key kept
  in your desktop keyring (or, without one, in a file only you can read).
- The engine never writes the running configuration to disk. A Tailscale node's keys, and a file your devices send
  until unbraid has saved it in your Downloads folder, stay in the engine's own folder, which only root can read.
- The list of installed apps is read on your computer, so you can assign routes, and never leaves it.
- Statistics, when you turn them on, and speed test results are kept only on your computer.

## What it connects to

- **Your VPN servers:** the provider servers your routes use, or your own WireGuard, OpenVPN or Shadowsocks servers.
  As with any VPN, they carry the traffic of the apps you route through them.
- **Your VPN provider's service**, when you sign in and to fetch its servers. A login only ever goes to its own
  provider.
  - NordVPN: `api.nordvpn.com`, and `downloads.nordcdn.com` for its OpenVPN files.
  - Mullvad: `api.mullvad.net`.
  - Private Internet Access: `www.privateinternetaccess.com` and `serverlist.piaservers.net`.
  - IVPN: `api.ivpn.net`.
  - Surfshark: `api.surfshark.com`.
  - Windscribe: `assets.windscribe.com`.
  - AirVPN: `airvpn.org`.
  - ExpressVPN, Proton VPN, Surfshark and AirVPN: the server lists that the gluetun project publishes on GitHub
    (`raw.githubusercontent.com`). Nothing about you is sent with these requests.
- **Tailscale**, when you turn it on: its control server (Tailscale's own, or your Headscale server), the relay servers
  that the control server names, and your own devices. The engine is built without Tailscale's log upload.
- **Connection checks**, while connected. Through each tunnel, a small STUN query to `stun.l.google.com` or
  `stun.cloudflare.com`, or a TLS handshake with `www.google.com`, shows that the tunnel still carries traffic. When
  every tunnel fails, one HTTPS request to `www.google.com` over your own network tells whether your network or the
  servers are down.
- **Your exits' addresses**, while Routes is on screen. After a connect or a server change, one request through each
  tunnel to Cloudflare's trace page (`www.cloudflare.com` or `one.one.one.one`) shows the address the tunnel leaves
  from. It is never made for Direct.
- **Name lookups:**
  - An app on a VPN route has its names looked up inside that route's tunnel, by the resolver its server or provider
    gives, or else by Quad9 (`9.9.9.9`).
  - Apps set to Direct, and the VPN servers' own names, are looked up with your computer's own resolver.
  - A DNS filter you set in unbraid replaces these where you apply it.
  - A name under a domain one of your networks gives (your router's own, a work VPN's) is looked up by that network's
    resolver, through that network, for every app and whatever the filter: no other resolver knows it. Those domains
    are systemd-resolved's for each network, or else the `search` line of `/etc/resolv.conf`, which without one is the
    domain of the computer's own name. A domain of one label never counts, so no network can take a whole top-level
    domain such as `com`.
- **Speed tests**, only when you start one, after you agree to M-Lab's terms. The test uses M-Lab's Locate service
  (`locate.measurementlab.net`) and the M-Lab server it names, through the exit being tested. M-Lab publishes every
  result with the address it came from, which is that exit's: see
  [M-Lab's privacy policy](https://www.measurementlab.net/privacy/).

Each of these services handles what it receives under its own privacy policy.

Links in the app, such as a provider's account page, open in your web browser. unbraid doesn't check for updates or
download anything else: the introduction film, the fonts and the icons come in the package.

To report a security problem, see [SECURITY.md](SECURITY.md).
