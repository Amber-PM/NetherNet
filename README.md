<h1 align="center">
  <a href="https://github.com/Amber-PM/NetherNet">
    <img src=".github/readme/amberpm.png" width="128" height="128" alt="AmberPM Logo" title="AmberPM" />
  </a>
</h1>

<p align="center">
  <strong>NetherNet transport for PHP</strong>
  <br />
  The WebRTC transport used by Minecraft: Bedrock Edition
</p>

<p align="center">
  <a href="https://github.com/Amber-PM/NetherNet/actions/workflows/ci.yml"><img src="https://github.com/Amber-PM/NetherNet/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
</p>

---

NetherNet only handles the transport: signaling, identity, framing and connection lifecycle. Packets and gameplay belong to the server.

## Requirements

- PHP 8.1+ with OpenSSL
- [ext-rtc](https://github.com/Amber-PM/ext-rtc) built for the running PHP (ZTS for Amber)

## Usage

```php
$transport = new Transport($config, $identityHandler, $listener,
	static fn() => new ExtRtcPeer($config, 20000, 20127, $bindAddress));
```

- **Port range** `20000, 20127` gives each player its own UDP port.
- **One port** for everyone with `udpMux: true` and `begin === end`. On Windows it needs an explicit bind address.
- **Behind port forwarding** pass `advertisedAddress: 'public ip'`. The forwarded port must match the local one.
- `Connection::send()` returning `ACCEPTED` means local admission, not delivery.
- `Connection::getStats()` returns RTT and byte counters while open.

## Development

```bash
composer check
php -d extension=/path/to/rtc.so vendor/bin/phpunit -c phpunit.rtc.xml.dist
```

Without ext-rtc use `composer install --ignore-platform-req=ext-rtc` for the fake backend tests. `ExtWebRtcPeer` remains as a legacy backend; never load ext-rtc and ext-webrtc together.

## References

- [Mojang NetherNet guide](https://mojang.github.io/bedrock-protocol-docs/guides/nether-net-onboarding-guide/)

## License

[LGPL-3.0-only](LICENSE)
