# NetherNet
[![CI](https://github.com/Amber-PM/NetherNet/actions/workflows/ci.yml/badge.svg)](https://github.com/Amber-PM/NetherNet/actions/workflows/ci.yml)

A standalone NetherNet transport library for PHP.

NetherNet handles the WebRTC transport layer for Minecraft: Bedrock Edition connections, acting as an alternative transport alongside RakNet.

```text
RakNet/RakLib ─┐
               ├─> NetworkSession -> protocolId -> MV layer
NetherNet ─────┘
```

This library focuses strictly on the transport connection itself. Packet decoding, session handling, and gameplay logic are left to the server implementation.

## Requirements

- PHP 8.1 or higher, with OpenSSL
- ext-webrtc 0.3.0 and libdatachannel 0.24.5 for the native backend
- A native extension built for the running PHP ABI; ZTS builds are required when
  embedding the library in Amber/PocketMine

Composer enforces the extension requirement. `ExtWebRtcPeer::assertAvailable()`
also verifies the libdatachannel version and native API before listening.
NetherNet stays transport-only; server packaging and operator trust provisioning
belong to the embedding application.

## Development

With the native backend installed, run tests and analysis with Composer:

```bash
composer check
```

Or run individual steps:

```bash
composer test
composer analyse
composer bench:check
```

Backend-independent development can install with
`composer install --ignore-platform-req=ext-webrtc` and run `composer test` and
`composer analyse`. This exemption only supports fake-backend unit tests; it does
not provide a working native transport. The library CI uses that explicit exemption
for its PHP/Windows unit matrix; Amber release CI builds and validates the pinned
native backend against PocketMine ZTS PHP. Run `composer test:native` with the real
extension to validate transport interoperability.

## License

NetherNet is licensed under the [LGPL-3.0-only](LICENSE).
