# Third-party software

unbraid is built on other people's work. This file lists what the app and its engine include or download and under which
licence. The complete licence texts, including every Go module linked into the engine, ship inside the app in
`app/src/main/resources/notices.txt` (Settings, Licences). `engine/notices.sh` regenerates that file after an engine
build.

## The engine (unbraid-engine)

| Component | Used for | Licence |
|---|---|---|
| [sing-box](https://github.com/SagerNet/sing-box) 1.14.4, its Linux daemon, with the patches in `engine/patches/` | The VPN engine | GPL-3.0-or-later |
| [wireguard-go](https://github.com/sagernet/wireguard-go) (SagerNet fork) | WireGuard inside the engine | MIT, Copyright WireGuard LLC |
| [Tailscale](https://github.com/tailscale/tailscale) | The built-in Tailscale client | BSD-3-Clause |
| [gVisor](https://github.com/google/gvisor) | The engine's network stack | Apache-2.0 |
| Go standard library and runtime | Part of the engine | BSD-3-Clause |
| Go modules linked into the engine | Protocols, crypto and networking in sing-box | Each module's own licence, listed with its full text in `notices.txt` |
| [uTLS](https://github.com/metacubex/utls) | TLS fingerprints | BSD-3-Clause, with parts under LGPL-3.0 (with a static-linking exception) and MIT |
| [lzokay](https://github.com/jackoalan/lzokay) | The LZO code in go-lzo derives from it | MIT |

## The app

| Component | Used for | Licence |
|---|---|---|
| [Slint](https://slint.dev) | User interface | GPL-3.0, one of Slint's licence choices |
| [Material Symbols](https://github.com/google/material-design-icons) | Icons | Apache-2.0 |
| The [Rust](https://www.rust-lang.org) standard library | Language runtime | Apache-2.0 or MIT |
| [tokio](https://tokio.rs), [tonic](https://github.com/hyperium/tonic), [prost](https://github.com/tokio-rs/prost) | The app's line to its engine | MIT; prost Apache-2.0 |
| [rustls](https://github.com/rustls/rustls) with [ring](https://github.com/briansmith/ring), and [reqwest](https://github.com/seanmonstar/reqwest) | TLS, always checking the certificate's name, and the providers' APIs | Apache-2.0, ISC and MIT |
| [rusqlite](https://github.com/rusqlite/rusqlite), with SQLite | Local statistics | MIT; SQLite is in the public domain |
| [rqrr](https://github.com/WanzenBug/rqrr) | Reads QR codes from a picture at sign-in | MIT or Apache-2.0, and ISC |
| [ksni](https://github.com/iovxw/ksni) and [zbus](https://github.com/dbus2/zbus) | The tray icon, and the desktop's portals and notifications | Unlicense; MIT |
| [resvg](https://github.com/linebender/resvg) | Drawing SVG icons | Apache-2.0 or MIT |
| About 350 more Rust crates | What the above build on | MIT, Apache-2.0, BSD, ISC, Zlib, Unicode and others, each in the app's full licence texts |
| [Big Shoulders Display](https://github.com/xotypeco/big_shoulders) | Font | SIL Open Font License 1.1 |
| [Onest](https://github.com/googlefonts/onest) | Font | SIL Open Font License 1.1 |
| [Martian Mono](https://github.com/evilmartians/mono) | Font | SIL Open Font License 1.1 |
| [gluetun](https://github.com/qdm12/gluetun) | ExpressVPN OpenVPN profile and provider notes | MIT |
| [PIA manual-connections](https://github.com/pia-foss/manual-connections) | Sign-in and region steps for Private Internet Access | MIT |
| PIA certificate authority (`pia_ca_rsa_4096.crt`) | Pinning TLS to PIA's WireGuard servers | MIT, from PIA manual-connections |

## Downloaded while the app runs

| Source | Used for | Licence |
|---|---|---|
| [gluetun-servers](https://github.com/qdm12/gluetun-servers) | Server lists for providers without a public API | MIT |
| Each provider's own API | Server lists, sign-in and keys | The provider's terms |

## Build tools

Cargo and the Rust compiler are under the Apache License 2.0 or MIT. slint-build (GPL-3.0, as Slint) compiles the
interface; protox (Apache-2.0 or MIT) and tonic-prost-build (MIT) compile the engine's .proto files, without protoc.
Cargo checks every crate it downloads against the checksum pinned in Cargo.lock. The tests also use rcgen (Apache-2.0
or MIT), which is not part of the app.

If you think something is missing or credited wrongly, please open an issue.
