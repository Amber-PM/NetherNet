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

- PHP 8.1 or higher

## Development

Run tests and analysis locally with Composer:

```bash
composer check
```

Or run individual steps:

```bash
composer test
composer analyse
composer bench:check
```

## License

NetherNet is licensed under the [LGPL-3.0-only](LICENSE).
