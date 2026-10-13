<?php

declare(strict_types=1);

namespace amber\nethernet\tests\signaling;

use amber\nethernet\signaling\HttpParseState;
use amber\nethernet\signaling\HttpRequestParser;
use amber\nethernet\TransportConfig;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class HttpRequestParserTest extends TestCase{
	public function testEverySplitPreservesBodyAndOpaqueId() : void{
		$body = "v=0\r\no=- 123 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=candidate:1 1 UDP 1 127.0.0.1 1234 typ host\r\n";
		$wire = "POST /v1/join/opaque%3Aid+%E2%98%83 HTTP/1.1\r\nHost: [::1]:19132\r\nContent-Type: application/sdp\r\nContent-Length: " . strlen($body) . "\r\n\r\n" . $body;
		for($split = 0; $split <= strlen($wire); ++$split){
			$parser = new HttpRequestParser(new TransportConfig());
			$parser->feed(substr($wire, 0, $split));
			$parser->feed(substr($wire, $split));
			self::assertSame(HttpParseState::COMPLETE, $parser->getState());
			self::assertSame(['networkId' => 'opaque:id+☃', 'body' => $body], $parser->takeRequest());
			self::assertSame(0, $parser->getBufferedBytes());
			self::assertNull($parser->takeRequest());
		}
	}

	public function testOneByteFragmentsAndGet() : void{
		$parser = new HttpRequestParser(new TransportConfig());
		foreach(str_split("GET /v1/join HTTP/1.1\r\nHost: example.test\r\nX-Unused: first\r\nX-Unused: second\r\n\r\n") as $byte){ $parser->feed($byte); }
		$parser->eof();
		self::assertSame(['networkId' => null, 'body' => ''], $parser->takeRequest());
	}

	public function testTildeInOpaqueIdAndHeaderToken() : void{
		$parser = new HttpRequestParser(new TransportConfig());
		$parser->feed("POST /v1/join/id~suffix HTTP/1.1\r\nHost: test\r\nX~Other: ok\r\nContent-Type: application/sdp\r\nContent-Length: 3\r\n\r\nabc");
		self::assertSame(['networkId' => 'id~suffix', 'body' => 'abc'], $parser->takeRequest());
	}

	/** @return iterable<string, array{string, int}> */
	public static function rejectedRequests() : iterable{
		$get = "GET /v1/join HTTP/1.1\r\n";
		$post = "POST /v1/join/id HTTP/1.1\r\nHost: test\r\nContent-Type: application/sdp\r\n";
		yield 'bare lf' => ["GET /v1/join HTTP/1.1\nHost: test\n\n", 400];
		yield 'bare cr' => [$get . "Host: te\rst\r\n\r\n", 400];
		yield 'no host' => [$get . "\r\n", 400];
		yield 'empty host' => [$get . "Host: \r\n\r\n", 400];
		yield 'host comma' => [$get . "Host: a,b\r\n\r\n", 400];
		yield 'host credentials' => [$get . "Host: a@b\r\n\r\n", 400];
		yield 'wrong http version' => [str_replace('HTTP/1.1', 'HTTP/1.0', $get) . "Host: test\r\n\r\n", 400];
		yield 'absolute target' => ["GET http://test/v1/join HTTP/1.1\r\nHost: test\r\n\r\n", 400];
		yield 'duplicate host' => [$get . "Host: test\r\nhOST: test\r\n\r\n", 400];
		yield 'duplicate length' => [$post . "Content-Length: 3\r\ncontent-length: 3\r\n\r\nabc", 400];
		yield 'length list' => [$post . "Content-Length: 3, 3\r\n\r\nabc", 400];
		yield 'length sign' => [$post . "Content-Length: +3\r\n\r\nabc", 400];
		yield 'length hex' => [$post . "Content-Length: 0x3\r\n\r\nabc", 400];
		yield 'overflow' => [$post . 'Content-Length: ' . str_repeat('9', 300) . "\r\n\r\n", 413];
		yield 'missing length' => [$post . "\r\n", 411];
		yield 'empty offer' => [$post . "Content-Length: 0\r\n\r\n", 400];
		yield 'transfer encoding' => [$post . "Transfer-Encoding: chunked\r\n\r\n", 501];
		yield 'te cl' => [$post . "Transfer-Encoding: identity\r\nContent-Length: 3\r\n\r\nabc", 400];
		yield 'duplicate te' => [$post . "Transfer-Encoding: chunked\r\ntransfer-encoding: identity\r\n\r\n", 400];
		yield 'connection nominated framing' => [$post . "Connection: content-length\r\nContent-Length: 3\r\n\r\nabc", 400];
		yield 'upgrade' => [$get . "Host: test\r\nUpgrade: websocket\r\n\r\n", 400];
		yield 'obs fold' => [$get . "Host: test\r\n X-Other: foo\r\n\r\n", 400];
		yield 'colon whitespace' => [$get . "Host : test\r\n\r\n", 400];
		yield 'control before trimming' => [$get . "Host: test\0\r\n\r\n", 400];
		yield 'high header byte' => [$get . "Host: test\r\nX: \xff\r\n\r\n", 400];
		yield 'duplicate type' => [$post . "Content-Type: application/sdp\r\nContent-Length: 3\r\n\r\nabc", 400];
		yield 'expect' => [$post . "Expect: 100-continue\r\nContent-Length: 3\r\n\r\nabc", 417];
		yield 'content encoding' => [$post . "Content-Encoding: gzip\r\nContent-Length: 3\r\n\r\nabc", 415];
		yield 'get body' => [$get . "Host: test\r\nContent-Length: 3\r\n\r\nabc", 400];
		yield 'get body without length' => [$get . "Host: test\r\n\r\nX", 400];
		yield 'pipeline' => [$get . "Host: test\r\n\r\n" . $get . "Host: test\r\n\r\n", 400];
		yield 'long body' => [$post . "Content-Length: 3\r\n\r\nabcX", 400];
		yield 'method' => ["HEAD /v1/join HTTP/1.1\r\nHost: test\r\n\r\n", 405];
		yield 'wrong route' => ["GET /other HTTP/1.1\r\nHost: test\r\n\r\n", 404];
		yield 'wrong content type' => [str_replace('application/sdp', 'application/sdp-json', $post) . "Content-Length: 3\r\n\r\nabc", 415];
		yield 'misleading charset' => [str_replace('application/sdp', 'application/sdp; charset=latin1', $post) . "Content-Length: 3\r\n\r\nabc", 415];
		yield 'unknown parameter' => [str_replace('application/sdp', 'application/sdp; boundary=x', $post) . "Content-Length: 3\r\n\r\nabc", 415];
		foreach(['id%00', 'id%2fextra', 'id%5cextra', '%252f', 'id%3fextra', 'id%23extra', '%2e%2e', 'id%', 'id%GG', 'id/extra', 'id?x=y', 'id#x', 'id%ff', 'id%7f'] as $id){
			yield 'path ' . $id => [str_replace('/id ', '/' . $id . ' ', $post) . "Content-Length: 3\r\n\r\nabc", 400];
		}
	}

	#[DataProvider('rejectedRequests')]
	public function testRejectedAtEverySplit(string $wire, int $status) : void{
		for($split = 0; $split <= strlen($wire); ++$split){
			$parser = new HttpRequestParser(new TransportConfig());
			$parser->feed(substr($wire, 0, $split));
			$parser->feed(substr($wire, $split));
			self::assertSame(HttpParseState::FAILED, $parser->getState(), 'split ' . $split);
			self::assertSame($status, $parser->getError()?->status);
			self::assertNull($parser->takeRequest());
			self::assertSame(0, $parser->getBufferedBytes());
		}
	}

	public function testPartialEofAndStorageRelease() : void{
		$wire = "POST /v1/join/id HTTP/1.1\r\nHost: test\r\nContent-Type: application/sdp\r\nContent-Length: 3\r\n\r\nabc";
		for($length = 0; $length < strlen($wire); ++$length){
			$parser = new HttpRequestParser(new TransportConfig());
			$parser->feed(substr($wire, 0, $length));
			$parser->eof();
			self::assertSame(400, $parser->getError()?->status);
			self::assertSame(0, $parser->getBufferedBytes());
		}
	}

	public function testExactLimitsLeadingZerosAndUtf8Charset() : void{
		$head = "POST /v1/join/ab HTTP/1.1\r\nHost: test\r\nContent-Type: Application/SDP; charset=\"UTF-8\"\r\nContent-Length: 0003\r\n\r\n";
		$parser = new HttpRequestParser(new TransportConfig(maxHttpHeaderBytes: strlen($head), maxSdpBytes: 3, maxNetworkIdBytes: 2));
		$parser->feed($head . 'abc');
		self::assertSame(['networkId' => 'ab', 'body' => 'abc'], $parser->takeRequest());
		foreach([new TransportConfig(maxHttpHeaderBytes: strlen($head) - 1), new TransportConfig(maxSdpBytes: 2), new TransportConfig(maxNetworkIdBytes: 1)] as $config){
			$parser = new HttpRequestParser($config);
			$parser->feed($head . 'abc');
			self::assertContains($parser->getError()?->status, [431, 413, 414]);
		}
	}

	public function testHugeInputIsNotRetainedAndExtraBytesAfterConsumptionFail() : void{
		$parser = new HttpRequestParser(new TransportConfig(maxHttpHeaderBytes: 64));
		$parser->feed(str_repeat('a', 1_000_000));
		self::assertSame(431, $parser->getError()?->status);
		self::assertSame(0, $parser->getBufferedBytes());
		$parser = new HttpRequestParser(new TransportConfig());
		$parser->feed("GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
		$parser->takeRequest();
		$parser->feed('X');
		self::assertSame(400, $parser->getError()?->status);
	}
}
