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
| [Compose Multiplatform](https://github.com/JetBrains/compose-multiplatform), AndroidX, Material 3, Material Symbols | User interface | Apache-2.0 |
| [Skia](https://skia.org), through [Skiko](https://github.com/JetBrains/skiko) | Drawing the interface | BSD-3-Clause |
| Kotlin standard library, kotlinx.coroutines, kotlinx.serialization | Language runtime | Apache-2.0 |
| [gRPC Java](https://github.com/grpc/grpc-java), [gRPC Kotlin](https://github.com/grpc/grpc-kotlin), [Netty](https://netty.io), Guava | The app's line to its engine | Apache-2.0 |
| [Protocol Buffers](https://github.com/protocolbuffers/protobuf) (lite runtime) | The engine's messages | BSD-3-Clause |
| [sqlite-jdbc](https://github.com/xerial/sqlite-jdbc), with SQLite | Local statistics | Apache-2.0; SQLite is in the public domain |
| [ZXing](https://github.com/zxing/zxing) core 3.5.3 | Reads QR codes from a picture at sign-in | Apache-2.0 |
| ThreeTenBP | Date and time code inside the Kotlin standard library | BSD-3-Clause |
| [Big Shoulders Display](https://github.com/xotypeco/big_shoulders) | Font | SIL Open Font License 1.1 |
| [Onest](https://github.com/googlefonts/onest) | Font | SIL Open Font License 1.1 |
| [Martian Mono](https://github.com/evilmartians/mono) | Font | SIL Open Font License 1.1 |
| [gluetun](https://github.com/qdm12/gluetun) | ExpressVPN OpenVPN profile and provider notes | MIT |
| [PIA manual-connections](https://github.com/pia-foss/manual-connections) | Sign-in and region steps for Private Internet Access | MIT |
| PIA certificate authority (`pia_ca_rsa_4096.crt`) | Pinning TLS to PIA's WireGuard servers | MIT, from PIA manual-connections |

The app runs on your distribution's Java runtime (OpenJDK, GPL-2.0 with the Classpath Exception), which the packages
depend on rather than include.

## Downloaded while the app runs

| Source | Used for | Licence |
|---|---|---|
| [gluetun-servers](https://github.com/qdm12/gluetun-servers) | Server lists for providers without a public API | MIT |
| Each provider's own API | Server lists, sign-in and keys | The provider's terms |

## Build tools

Gradle, the Kotlin compiler, the Compose Multiplatform Gradle plugin and the Protocol Buffers Gradle plugin are under
the Apache License 2.0; protoc and its gRPC plugins under BSD-3-Clause and Apache-2.0. The Gradle wrapper checks the
Gradle distribution it downloads against a pinned SHA-256 checksum. The unit tests use JUnit 4.13.2 (EPL-1.0), Hamcrest
Core 1.3 (BSD-3-Clause) and Compose's UI test library (Apache-2.0), which are not part of the app.

If you think something is missing or credited wrongly, please open an issue.
