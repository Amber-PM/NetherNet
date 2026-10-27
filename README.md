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
- ext-rtc (`amber\rtc`, API version 1, libdatachannel 0.24.6) for the native
  backend; ext-rtc itself targets PHP 8.4.27 and 8.5.12
- A native extension built for the running PHP ABI; ZTS builds are required when
  embedding the library in Amber/PocketMine

Composer enforces the extension requirement. `ExtRtcPeer::assertAvailable()`
also verifies the native API version, classes and capabilities before listening.
NetherNet stays transport-only; server packaging and operator trust provisioning
belong to the embedding application.

## Sending and callbacks

`Connection::send()` returning `ACCEPTED` means local admission, not delivery.
Its completion callback runs at most once: `true` when all frames reach the local
backend, `false` on rejection or cancellation. Callback failures do not change
admission or retry submitted frames; they close only the affected connection
(`callback_error`). `onClose` runs once. Native cleanup errors still propagate.

## Native backend

`Transport` uses `ExtRtcPeer` (ext-rtc) unless a peer factory is passed. Pass a
factory to set ICE ports, the bind address or UDP mux:

```php
// own UDP port per peer, from a bounded range
$transport = new Transport($config, $identityHandler, $listener,
	static fn() => new ExtRtcPeer($config, 20000, 20127, $bindAddress));
// every peer shares one UDP port
$transport = new Transport($config, $identityHandler, $listener,
	static fn() => new ExtRtcPeer($config, 19133, 19133, $bindAddress, udpMux: true));
// behind port forwarding (containers, hosting): also offer the public address
$transport = new Transport($config, $identityHandler, $listener,
	static fn() => new ExtRtcPeer($config, 19133, 19133, null, udpMux: true, advertisedAddress: '203.0.113.7'));
```

- Bind addresses must be numeric and exist locally; ext-rtc rejects ranges
  starting below 1024 and ending at 65535.
- UDP mux needs one fixed port (`begin === end`) and does not support TURN. All
  mux peers in a process must use the same bind address for a port; a conflicting
  or busy port fails peer construction (`backend_error`) instead of falling back.
- On Windows, mux requires an explicit, non-wildcard bind address. With a wildcard
  bind the pinned libjuice can stall the next mux negotiation for about a minute
  after a mux peer closes. `ExtRtcPeer::assertMuxOptions()` checks this upfront.
- An advertised address adds, after each local UDP host candidate of the same IP
  family, a copy with that address and the same port. The local candidates stay,
  so clients on the same network still connect directly. The forwarded public port
  must equal the local ICE port, which a fixed mux port makes predictable.
- Well-formed remote candidates the backend cannot use (TCP, mDNS hostnames,
  RTCP component 2) are dropped before negotiation; malformed candidates still
  fail it.
- `sendFrame()` returning `false` indicates native send backpressure.

`ExtWebRtcPeer` (ext-webrtc 0.3.0) remains available as an explicit legacy
backend. Composer only suggests ext-webrtc. Never load ext-rtc and ext-webrtc in
the same PHP process.

Run ext-rtc tests without ext-webrtc loaded. Interop runs an independent client
in a separate process, either ext-webrtc or any executable speaking the
`tests/rtc/support/webrtc-client.php` line protocol:

```bash
php -d extension=/path/to/rtc.so vendor/bin/phpunit -c phpunit.rtc.xml.dist
NETHERNET_WEBRTC_MODULE=/path/to/webrtc.so php -d extension=/path/to/rtc.so vendor/bin/phpunit -c phpunit.rtc.xml.dist --group interop
NETHERNET_INTEROP_CLIENT=/path/to/client php -d extension=/path/to/rtc.so vendor/bin/phpunit -c phpunit.rtc.xml.dist --group interop
```

The interop test needs non-blocking process pipes, which PHP lacks on Windows.

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
`composer install --ignore-platform-req=ext-rtc` and run `composer test` and
`composer analyse`. This exemption only supports fake-backend unit tests; it does
not provide a working native transport. The library CI uses that explicit exemption
for its PHP/Windows unit matrix. Run the `phpunit.rtc.xml.dist` suite with ext-rtc
loaded to validate the native transport. `composer test:native` covers the legacy
ext-webrtc backend.

## License

NetherNet is licensed under the [LGPL-3.0-only](LICENSE).
