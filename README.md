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

## Sending and callbacks

`Connection::send()` returning `ACCEPTED` means local admission, not delivery.
Its completion callback runs at most once: `true` when all frames reach the local
backend, `false` on rejection or cancellation. Callback failures do not change
admission or retry submitted frames; they close only the affected connection
(`callback_error`). `onClose` runs once. Native cleanup errors still propagate.

## ext-rtc backend (opt-in)

`ExtRtcPeer` uses ext-rtc (`amber\rtc`, API version 1, libdatachannel 0.24.6).
`ExtWebRtcPeer` remains the default. Opt in with a peer factory:

```php
$transport = new Transport($config, $identityHandler, $listener,
	static fn() => new ExtRtcPeer($config, $icePortBegin, $icePortEnd, $bindAddress));
```

Limitations:

- UDP mux is unsupported; each peer needs its own UDP port. Bind addresses must
  exist locally; ext-rtc rejects ranges starting below 1024 and ending at 65535.
- `sendFrame()` returning `false` indicates native send backpressure.
- Composer still requires ext-webrtc 0.3.0, even with ext-rtc.
- Do not load ext-rtc and ext-webrtc in the same PHP process.

Run ext-rtc tests without ext-webrtc loaded. Interop runs ext-webrtc in a
separate process:

```bash
php -d extension=/path/to/rtc.so vendor/bin/phpunit -c phpunit.rtc.xml.dist
NETHERNET_WEBRTC_MODULE=/path/to/webrtc.so php -d extension=/path/to/rtc.so vendor/bin/phpunit -c phpunit.rtc.xml.dist --group interop
```

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
