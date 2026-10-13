<?php

declare(strict_types=1);

namespace amber\nethernet\tests\signaling;

use amber\nethernet\signaling\HttpResponse;
use amber\nethernet\signaling\ServerMetadata;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class HttpResponseTest extends TestCase{
	public function testExactWireAndMetadataTypes() : void{
		$metadata = new ServerMetadata('My "server" ☃', 123, 'version', 'World', 2, 10, 1);
		$json = '{"name":"My \"server\" ☃","protocol":123,"version":"version","level":"World","players":2,"maxPlayers":10,"gameType":1}';
		self::assertSame($json, $metadata->toJson());
		$response = new HttpResponse(200, $json, 'application/json');
		self::assertSame("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " . strlen($json) . "\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n" . $json, $response->encode());
	}

	public function testSdpBytesAndSafeFixedErrors() : void{
		$sdp = "v=0\r\ns=☃\r\n";
		self::assertSame("HTTP/1.1 200 OK\r\nContent-Type: application/sdp\r\nContent-Length: 12\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n" . $sdp, (new HttpResponse(200, $sdp, 'application/sdp'))->encode());
		self::assertSame("HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 18\r\nConnection: close\r\nCache-Control: no-store\r\nAllow: GET\r\n\r\nMethod Not Allowed", HttpResponse::error(405, 'GET')->encode());
	}

	/** @return iterable<array{int, string, ?string}> */
	public static function unsafeHeaders() : iterable{
		yield [200, "application/sdp\r\nX: injected", null];
		yield [200, 'text/html', null];
		yield [200, 'application/sdp', "GET\r\nX: injected"];
		yield [100, 'application/sdp', null];
	}

	#[DataProvider('unsafeHeaders')]
	public function testUnsafeHeadersRejected(int $status, string $type, ?string $allow) : void{
		$this->expectException(\InvalidArgumentException::class);
		new HttpResponse($status, '', $type, $allow);
	}

	/** @return iterable<array{string, int, string, string, int, int, int}> */
	public static function invalidMetadata() : iterable{
		yield ['a', -1, 'b', 'c', 0, 1, 0];
		yield ['a', 1, 'b', 'c', -1, 1, 0];
		yield ['a', 1, 'b', 'c', 0, -1, 0];
		yield ['a', 1, 'b', 'c', 0, 1, 3];
		yield ["a\r\n", 1, 'b', 'c', 0, 1, 0];
		yield ["\xff", 1, 'b', 'c', 0, 1, 0];
		yield [str_repeat('a', 1025), 1, 'b', 'c', 0, 1, 0];
		yield ['a', 1, "b\0", 'c', 0, 1, 0];
	}

	#[DataProvider('invalidMetadata')]
	public function testInvalidMetadataRejected(string $name, int $protocol, string $version, string $level, int $players, int $maxPlayers, int $gameType) : void{
		$this->expectException(\InvalidArgumentException::class);
		new ServerMetadata($name, $protocol, $version, $level, $players, $maxPlayers, $gameType);
	}
}
