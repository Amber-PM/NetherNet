<?php

declare(strict_types=1);

namespace amber\nethernet\tests;

use amber\nethernet\SignalingPeerAddress;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SignalingPeerAddressTest extends TestCase{
	/** @return iterable<string, array{string, string, int}> */
	public static function endpoints() : iterable{
		yield 'IPv4' => ['127.0.0.1:12345', '127.0.0.1', 12345];
		yield 'IPv6' => ['[::1]:54321', '::1', 54321];
		yield 'mapped IPv6' => ['[::ffff:192.0.2.1]:65535', '::ffff:192.0.2.1', 65535];
	}

	#[DataProvider('endpoints')]
	public function testSocketEndpoints(string $endpoint, string $ip, int $port) : void{
		$address = SignalingPeerAddress::fromSocketName($endpoint);
		self::assertSame($ip, $address->ip);
		self::assertSame($port, $address->port);
	}

	/** @return iterable<string, array{string}> */
	public static function invalidEndpoints() : iterable{
		foreach(['localhost:1234', '127.0.0.1:0', '127.0.0.1:65536', '127.0.0.1:-1', '[::1]:80/path', '::1:80', '[127.0.0.1]:80', '999.1.1.1:80', "127.0.0.1:80\n"] as $endpoint){ yield $endpoint => [$endpoint]; }
	}

	#[DataProvider('invalidEndpoints')]
	public function testRejectsUntrustedOrMalformedEndpoints(string $endpoint) : void{
		$this->expectException(\InvalidArgumentException::class);
		SignalingPeerAddress::fromSocketName($endpoint);
	}

	/** @return iterable<string, array{string, int}> */
	public static function invalidValues() : iterable{
		yield 'hostname' => ['localhost', 80];
		yield 'invalid IP' => ['999.1.1.1', 80];
		yield 'zero port' => ['::1', 0];
		yield 'overflow port' => ['127.0.0.1', 65536];
	}

	#[DataProvider('invalidValues')]
	public function testConstructorRequiresNumericIpAndValidPort(string $ip, int $port) : void{
		$this->expectException(\InvalidArgumentException::class);
		new SignalingPeerAddress($ip, $port);
	}
}
