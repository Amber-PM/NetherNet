<?php

declare(strict_types=1);

namespace amber\nethernet\tests\signaling;

use amber\nethernet\signaling\ProxyProtocol;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ProxyProtocolTest extends TestCase{
	private const V2 = "\r\n\r\n\0\r\nQUIT\n";

	/** @return array{string, int, int} */
	private static function source(string $bytes) : array{
		$parsed = ProxyProtocol::parse($bytes);
		self::assertNotNull($parsed);
		self::assertNotNull($parsed[0]);
		return [$parsed[0]->ip, $parsed[0]->port, $parsed[1]];
	}

	public function testVersionOneNamesTheSourceAndLeavesTheRequest() : void{
		$header = "PROXY TCP4 203.0.113.9 10.0.0.1 51000 19132\r\n";
		self::assertSame(['203.0.113.9', 51000, strlen($header)], self::source($header . 'GET /'));
		self::assertSame(['2001:db8::9', 51000, 48], self::source("PROXY TCP6 2001:db8::9 2001:db8::1 51000 19132\r\n"));
	}

	public function testVersionTwoNamesTheSource() : void{
		$v4 = self::V2 . "\x21\x11" . pack('n', 12) . inet_pton('203.0.113.9') . inet_pton('10.0.0.1') . pack('nn', 51000, 19132);
		self::assertSame(['203.0.113.9', 51000, 28], self::source($v4 . 'rest'));
		// extra tlv bytes are skipped
		$v6 = self::V2 . "\x21\x21" . pack('n', 39) . inet_pton('2001:db8::9') . inet_pton('2001:db8::1') . pack('nn', 51000, 19132) . "\x04\x00\x00";
		self::assertSame(['2001:db8::9', 51000, 55], self::source($v6));
	}

	public function testUnknownAndLocalKeepTheSocketAddress() : void{
		self::assertSame([null, 15], ProxyProtocol::parse("PROXY UNKNOWN\r\n"));
		self::assertSame([null, 16], ProxyProtocol::parse(self::V2 . "\x20\x00\x00\x00"));
	}

	public function testPartialHeadersWaitForMoreBytes() : void{
		foreach(['P', 'PROXY TCP4 203.0.113.9 10.0.0.1 51000 19132', "\r\n\r\n", self::V2 . "\x21\x11\x00\x0c1234"] as $partial){
			self::assertNull(ProxyProtocol::parse($partial));
		}
	}

	/** @return iterable<string, array{string}> */
	public static function malformed() : iterable{
		yield 'http request' => ["GET /v1/join HTTP/1.1\r\n"];
		yield 'bad family' => ["PROXY TCP5 203.0.113.9 10.0.0.1 51000 19132\r\n"];
		yield 'family mismatch' => ["PROXY TCP4 2001:db8::9 10.0.0.1 51000 19132\r\n"];
		yield 'hostname' => ["PROXY TCP4 example.com 10.0.0.1 51000 19132\r\n"];
		yield 'zero port' => ["PROXY TCP4 203.0.113.9 10.0.0.1 0 19132\r\n"];
		yield 'port above maximum' => ["PROXY TCP4 203.0.113.9 10.0.0.1 70000 19132\r\n"];
		yield 'overlong v1' => ['PROXY ' . str_repeat('a', 120)];
		yield 'v2 wrong version' => [self::V2 . "\x11\x11\x00\x0c" . str_repeat("\0", 12)];
		yield 'v2 udp' => [self::V2 . "\x21\x12\x00\x0c" . str_repeat("\1", 12)];
		yield 'v2 short addresses' => [self::V2 . "\x21\x11\x00\x08" . str_repeat("\1", 8)];
		yield 'v2 oversized' => [self::V2 . "\x21\x11\xff\xff"];
	}

	#[DataProvider('malformed')]
	public function testRejectsMalformedHeaders(string $bytes) : void{
		$this->expectException(\InvalidArgumentException::class);
		ProxyProtocol::parse($bytes);
	}

	public function testTrustedNetworksMatchAddressesAndPrefixes() : void{
		$networks = ['10.0.0.5', '192.168.0.0/22', '2001:db8::/33', '::1'];
		ProxyProtocol::assertNetworks($networks);
		foreach(['10.0.0.5' => true, '10.0.0.6' => false, '192.168.3.255' => true, '192.168.4.0' => false, '2001:db8:7fff::1' => true, '2001:db8:8000::1' => false, '::1' => true, '127.0.0.1' => false] as $ip => $expected){
			self::assertSame($expected, ProxyProtocol::matches($ip, $networks), $ip);
		}
		self::assertFalse(ProxyProtocol::matches('10.0.0.5', []));
		self::assertTrue(ProxyProtocol::matches('::ffff:10.0.0.5', $networks));
		self::assertFalse(ProxyProtocol::matches('::ffff:10.0.0.6', $networks));
		self::assertTrue(ProxyProtocol::matches('203.0.113.1', ['0.0.0.0/0']));
		self::assertFalse(ProxyProtocol::matches('2001:db8::1', ['0.0.0.0/0']));
		foreach(['proxy.local', '10.0.0.0/33', '10.0.0.0/', '::1/129', '10.0.0.0/8/8'] as $invalid){
			try{ ProxyProtocol::assertNetworks([$invalid]); self::fail('accepted ' . $invalid); }catch(\InvalidArgumentException){ $this->addToAssertionCount(1); }
		}
	}
}
