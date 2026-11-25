<?php

declare(strict_types=1);

namespace amber\nethernet\tests\signaling;

use amber\nethernet\backend\WebRtcPeer;
use amber\nethernet\identity\ClientServerIdentityHandler;
use amber\nethernet\identity\SdpIdentity;
use amber\nethernet\ConnectionState;
use amber\nethernet\SignalingPeerConnection;
use amber\nethernet\signaling\HttpState;
use amber\nethernet\signaling\HttpServer;
use amber\nethernet\signaling\HttpSignaling;
use amber\nethernet\signaling\ServerMetadata;
use amber\nethernet\signaling\TlsConfig;
use amber\nethernet\tests\identity\IdentityFixture;
use amber\nethernet\tests\transport\FakePeer;
use amber\nethernet\tests\transport\RecordingListener;
use amber\nethernet\Transport;
use amber\nethernet\TransportConfig;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

final class HttpServerTest extends TestCase{
	private HttpServer $server;
	private HttpSignaling $http;
	private Transport $transport;
	private RecordingListener $listener;
	private FakePeer $peer;
	private IdentityFixture $fixture;
	private float $now = 0.0;
	/** @var list<resource> */
	private array $sockets = [];
	/** @var list<string> */
	private array $temporary = [];

	protected function setUp() : void{
		$this->fixture = new IdentityFixture();
		$this->listener = new RecordingListener();
		$this->peer = new FakePeer();
		$this->make();
	}

	/**
	 * @param \Closure(): float|null $clock
	 * @param \Closure(): ServerMetadata|null $metadata
	 * @param \Closure(string): bool|null $admit
	 * @param list<string> $trustedProxies
	 */
	private function make(?TransportConfig $config = null, int $ioBytes = 16384, ?\Closure $clock = null, ?\Closure $metadata = null, string $bind = 'tcp://127.0.0.1:0', ?\Closure $admit = null, array $trustedProxies = [], ?TlsConfig $tls = null) : void{
		$config ??= new TransportConfig();
		$this->http = new HttpSignaling($config, $metadata ?? static fn() => new ServerMetadata('Server', 12, 'custom', 'World', 0, 20, 0), $this->listener);
		$this->transport = new Transport($config, new ClientServerIdentityHandler($this->fixture->verifier(), $this->fixture->server, $config, static fn() => 1000), $this->http, fn() : WebRtcPeer => $this->peer, $clock, static fn() => 1000);
		$this->http->bind($this->transport);
		$this->server = new HttpServer($config, $this->http, $bind, ioBytes: $ioBytes, clock: $clock, admit: $admit, trustedProxies: $trustedProxies, tls: $tls);
	}

	protected function tearDown() : void{
		if(isset($this->server)){ $this->server->stop(); }
		if(isset($this->transport)){ $this->transport->stop(); }
		foreach($this->sockets as $socket){ if(is_resource($socket)){ fclose($socket); } }
		foreach($this->temporary as $directory){
			foreach(glob($directory . '/*') ?: [] as $file){ unlink($file); }
			rmdir($directory);
		}
	}

	/** @return resource */
	private function client(){
		$socket = stream_socket_client('tcp://' . $this->server->getAddress(), $code, $error, 1);
		self::assertNotFalse($socket);
		self::assertTrue(stream_set_blocking($socket, false));
		$this->sockets[] = $socket;
		return $socket;
	}

	/** @param resource $socket */
	private function response($socket, int $timeoutSeconds = 2) : string{
		$response = '';
		$deadline = hrtime(true) + $timeoutSeconds * 1_000_000_000;
		do{
			$this->transport->poll();
			$this->server->poll(1000);
			$bytes = fread($socket, 65536);
			self::assertNotFalse($bytes);
			$response .= $bytes;
			if(feof($socket)){ return $response; }
		}while(hrtime(true) < $deadline);
		self::fail('TCP response did not close within its test deadline');
	}

	public function testRealGetAndSlotRecovery() : void{
		$this->server->stop();
		$this->transport->stop();
		$this->make(new TransportConfig(maxHttpConnections: 1));
		for($i = 0; $i < 3; ++$i){
			$socket = $this->client();
			fwrite($socket, "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
			$response = $this->response($socket);
			self::assertStringStartsWith("HTTP/1.1 200 OK\r\n", $response);
			self::assertStringContainsString("Content-Type: application/json\r\n", $response);
			[, $body] = explode("\r\n\r\n", $response, 2);
			$metadata = json_decode($body, true, 16, JSON_THROW_ON_ERROR);
			self::assertIsArray($metadata);
			self::assertSame('Server', $metadata['name']);
			self::assertSame(0, $this->server->getConnectionCount());
			self::assertSame(0, $this->server->getBufferedBytes());
		}
	}

	/** @param resource $socket */
	private function send($socket, string $bytes) : void{
		$offset = 0;
		$deadline = hrtime(true) + 2_000_000_000;
		while($offset < strlen($bytes)){
			$written = fwrite($socket, substr($bytes, $offset));
			self::assertNotFalse($written);
			$offset += $written;
			$this->transport->poll();
			$this->server->poll(1000);
			if(hrtime(true) >= $deadline){ self::fail('TCP client send stalled'); }
		}
	}

	private function post(string $body, string $id = 'opaque%3Aid') : string{
		return "POST /v1/join/$id HTTP/1.1\r\nHost: test\r\nContent-Type: application/sdp\r\nContent-Length: " . strlen($body) . "\r\n\r\n" . $body;
	}

	public function testSocketAddressSurvivesHttpCleanupAndIgnoresClientClaims() : void{
		$offer = $this->fixture->offer(FakePeer::SDP);
		$ports = [];
		foreach(['203.0.113.10', '203.0.113.11'] as $claim){
			$socket = $this->client();
			$local = stream_socket_get_name($socket, false);
			self::assertNotFalse($local);
			$request = str_replace("Host: test\r\n", "Host: test\r\nX-Forwarded-For: $claim\r\nForwarded: for=$claim\r\n", $this->post($offer, $claim));
			$this->send($socket, $request);
			self::assertStringStartsWith('HTTP/1.1 200 OK', $this->response($socket));
			$this->transport->poll();
			$connection = $this->listener->connections[count($this->listener->connections)];
			self::assertInstanceOf(SignalingPeerConnection::class, $connection);
			$address = $connection->getSignalingPeerAddress();
			self::assertNotNull($address);
			self::assertSame('127.0.0.1', $address->ip);
			self::assertSame((int) substr($local, strrpos($local, ':') + 1), $address->port);
			self::assertSame($claim, $connection->getNetworkId());
			$ports[] = $address->port;
			self::assertSame(0, $this->server->getConnectionCount());
		}
		self::assertNotSame($ports[0], $ports[1]);
	}

	public function testOneByteHeadersAndBoundedPartialWrites() : void{
		$this->server->stop();
		$this->transport->stop();
		$this->make(ioBytes: 1);
		$socket = $this->client();
		$request = "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n";
		foreach(str_split($request) as $byte){ $this->send($socket, $byte); }
		for($i = 0; $i < 2000 && $this->http->getState(1) !== HttpState::WRITING; ++$i){ $this->server->poll(1000); }
		self::assertSame(HttpState::WRITING, $this->http->getState(1));
		$this->server->poll();
		self::assertSame(HttpState::WRITING, $this->http->getState(1));
		self::assertSame(1, $this->server->getConnectionCount());
		$response = $this->response($socket);
		self::assertStringStartsWith('HTTP/1.1 200 OK', $response);
		self::assertSame(1, substr_count($response, 'HTTP/1.1'));
		self::assertSame(HttpState::CLOSED, $this->http->getState(1));
	}

	public function testLargeFragmentedAuthenticatedPostAndOwnership() : void{
		$probe = $this->client();
		$this->send($probe, "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
		self::assertStringContainsString('200 OK', $this->response($probe));
		$base = FakePeer::SDP . 'a=x:' . str_repeat('z', 58000) . "\r\n";
		$body = $this->fixture->offer($base);
		self::assertLessThanOrEqual(65536, strlen($body));
		$socket = $this->client();
		foreach(str_split($this->post($body), 379) as $chunk){ $this->send($socket, $chunk); }
		$response = $this->response($socket);
		self::assertStringStartsWith('HTTP/1.1 200 OK', $response);
		self::assertStringContainsString("Content-Type: application/sdp\r\n", $response);
		[, $answer] = explode("\r\n\r\n", $response, 2);
		self::assertSame($this->listener->answers[1], $answer);
		self::assertSame($base, $this->peer->remoteSdp);
		$identity = SdpIdentity::fromSdp($answer, new TransportConfig());
		AnswerSignatures::verify($identity);
		self::assertSame(FakePeer::SDP, $identity->sdpWithoutIdentity);
		self::assertSame(HttpState::CLOSED, $this->http->getState(2));
		$this->transport->poll();
		self::assertSame('opaque:id', $this->listener->connections[1]->getNetworkId());
		self::assertSame(ConnectionState::OPEN, $this->listener->connections[1]->getState());
		$this->server->stop();
		self::assertSame(0, $this->peer->closes);
		$this->transport->stop();
		self::assertSame(1, $this->peer->closes);
	}

	public function testHalfCloseCompleteAndPrematureRequests() : void{
		$complete = $this->client();
		$this->send($complete, "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
		self::assertTrue(stream_socket_shutdown($complete, STREAM_SHUT_WR));
		self::assertStringStartsWith('HTTP/1.1 200 OK', $this->response($complete));
		$partial = $this->client();
		$this->send($partial, "POST /v1/join/id HTTP/1.1\r\nHost: test\r\nContent-Type: application/sdp\r\nContent-Length: 5\r\n\r\nv=");
		self::assertTrue(stream_socket_shutdown($partial, STREAM_SHUT_WR));
		self::assertStringStartsWith('HTTP/1.1 400 Bad Request', $this->response($partial));
		self::assertSame(0, $this->server->getConnectionCount());
	}

	public function testStaleWritingAnswerIsDiscardedWithoutSecondResponse() : void{
		$this->server->stop();
		$this->transport->stop();
		$this->make(ioBytes: 17);
		$this->peer->open = false;
		$socket = $this->client();
		$this->send($socket, $this->post($this->fixture->offer(FakePeer::SDP)));
		for($i = 0; $i < 1000 && $this->http->getState(1) !== HttpState::WRITING; ++$i){
			$this->transport->poll();
			$this->server->poll();
		}
		self::assertSame(HttpState::WRITING, $this->http->getState(1));
		$this->server->poll();
		$first = fread($socket, 65536);
		self::assertNotFalse($first);
		self::assertNotSame('', $first);
		$this->peer->state = 'FAILED';
		$this->transport->poll();
		self::assertSame(HttpState::CLOSED, $this->http->getState(1));
		$rest = $this->response($socket);
		self::assertSame('', $rest);
		self::assertSame(0, $this->server->getBufferedBytes());
		self::assertSame(1, $this->peer->closes);
	}

	private function timed(int $ioBytes = 16384) : void{
		$this->server->stop();
		$this->transport->stop();
		$this->make(new TransportConfig(httpHeaderTimeoutSeconds: 1, signalingTimeoutSeconds: 1), $ioBytes, fn() => $this->now);
	}

	public function testHeaderDeadlineIsAbsoluteAndSlotRecovers() : void{
		$this->timed();
		$socket = $this->client();
		$this->send($socket, 'G');
		$this->now = 0.75;
		$this->send($socket, 'E');
		$this->now = 1.0;
		$this->server->poll();
		self::assertStringStartsWith('HTTP/1.1 408 Request Timeout', $this->response($socket));
		self::assertSame(0, $this->server->getConnectionCount());
		$valid = $this->client();
		$this->send($valid, "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
		self::assertStringStartsWith('HTTP/1.1 200 OK', $this->response($valid));
	}

	public function testBodyDeadlineAndAnswerDeadlineCancelUnfinishedWork() : void{
		$this->timed();
		$body = $this->client();
		$this->send($body, "POST /v1/join/id HTTP/1.1\r\nHost: test\r\nContent-Type: application/sdp\r\nContent-Length: 8\r\n\r\nv=");
		for($i = 0; $i < 100 && $this->http->getState(1) !== HttpState::BODY; ++$i){ $this->server->poll(1000); }
		self::assertSame(HttpState::BODY, $this->http->getState(1));
		$this->now = 1.0;
		$this->server->poll();
		self::assertStringStartsWith('HTTP/1.1 408 Request Timeout', $this->response($body));
		$this->peer->gathered = false;
		$pending = $this->client();
		$this->send($pending, $this->post($this->fixture->offer(FakePeer::SDP)));
		for($i = 0; $i < 100 && $this->http->getState(2) !== HttpState::PENDING; ++$i){ $this->server->poll(1000); }
		self::assertSame(HttpState::PENDING, $this->http->getState(2));
		$this->transport->poll();
		$this->now = 2.0;
		$this->server->poll();
		self::assertNotSame(HttpState::PENDING, $this->http->getState(2));
		self::assertSame(1, $this->peer->closes);
		self::assertStringStartsWith('HTTP/1.1 504 Gateway Timeout', $this->response($pending));
	}

	public function testWritingDeadlineDoesNotResetOnProgress() : void{
		$this->timed(1);
		$socket = $this->client();
		$this->send($socket, "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
		for($i = 0; $i < 200 && $this->http->getState(1) !== HttpState::WRITING; ++$i){ $this->server->poll(1000); }
		self::assertSame(HttpState::WRITING, $this->http->getState(1));
		$this->now = 0.75;
		$this->server->poll();
		$this->now = 1.0;
		$this->server->poll();
		self::assertSame(HttpState::CLOSED, $this->http->getState(1));
		self::assertSame(0, $this->server->getConnectionCount());
		self::assertSame(0, $this->server->getBufferedBytes());
	}

	public function testRealClockSlowlorisTimesOutWithConcurrentValidClient() : void{
		$this->server->stop();
		$this->transport->stop();
		$this->make(new TransportConfig(httpHeaderTimeoutSeconds: 1));
		$slow = $this->client();
		$started = hrtime(true);
		$this->send($slow, 'G');
		$valid = $this->client();
		$this->send($valid, "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
		self::assertStringStartsWith('HTTP/1.1 200 OK', $this->response($valid));
		$nextByte = $started;
		$response = '';
		$reset = false;
		do{
			if(hrtime(true) >= $nextByte && $response === ''){
				if(@fwrite($slow, 'x') === false){ $reset = true; break; }
				$nextByte += 200_000_000;
			}
			$this->transport->poll();
			$this->server->poll(10000);
			$bytes = @fread($slow, 65536);
			if($bytes === false){ $reset = true; break; }
			$response .= $bytes;
		}while(!feof($slow) && hrtime(true) - $started < 2_000_000_000);
		self::assertTrue($reset || feof($slow));
		self::assertTrue(str_starts_with('HTTP/1.1 408 Request Timeout', substr($response, 0, strlen('HTTP/1.1 408 Request Timeout'))));
		self::assertSame(HttpState::CLOSED, $this->http->getState(1));
		self::assertSame(0, $this->server->getConnectionCount());
		self::assertGreaterThan(500_000_000, hrtime(true) - $started);
		self::assertLessThan(2_000_000_000, hrtime(true) - $started);
	}

	public function testClockFailureDuringAcceptanceDoesNotOrphanExchange() : void{
		$this->server->stop();
		$this->transport->stop();
		$calls = 0;
		$this->make(clock: static function() use (&$calls) : float{
			if(++$calls === 3){ throw new \RuntimeException('clock failed'); }
			return 0.0;
		});
		$this->client();
		try{
			$this->server->poll();
			self::fail('Clock failure did not propagate');
		}catch(\RuntimeException $e){ self::assertSame('clock failed', $e->getMessage()); }
		self::assertSame(HttpState::CLOSED, $this->http->getState(1));
		self::assertSame(0, $this->server->getConnectionCount());
	}

	/** @return iterable<string, array{string}> */
	public static function invalidBinds() : iterable{
		yield 'port wraps to ephemeral' => ['tcp://127.0.0.1:65536'];
		yield 'port wraps to another port' => ['tcp://127.0.0.1:99999'];
		yield 'invalid numeric address' => ['tcp://999.999.999.999:0'];
		yield 'hostname' => ['tcp://localhost:0'];
		yield 'tls' => ['tls://127.0.0.1:0'];
		yield 'unbracketed IPv6' => ['tcp://::1:0'];
		yield 'missing close bracket' => ['tcp://[::1:0'];
		yield 'missing open bracket' => ['tcp://::1]:0'];
		yield 'bracketed IPv4' => ['tcp://[127.0.0.1]:0'];
		yield 'malformed mapped IPv6' => ['tcp://[::ffff:999.0.0.1]:0'];
		yield 'empty host' => ['tcp://:0'];
		yield 'empty port' => ['tcp://127.0.0.1:'];
		yield 'negative port' => ['tcp://127.0.0.1:-1'];
		yield 'nonnumeric port' => ['tcp://127.0.0.1:http'];
		yield 'credentials' => ['tcp://user@127.0.0.1:0'];
		yield 'path' => ['tcp://127.0.0.1:0/path'];
		yield 'control' => ["tcp://[::1\n]:0"];
	}

	#[DataProvider('invalidBinds')]
	public function testInvalidBindIsRejectedBeforeOpeningListener(string $bind) : void{
		$this->expectException(\InvalidArgumentException::class);
		new HttpServer(new TransportConfig(), $this->http, $bind);
	}

	/** @return iterable<string, array{string, string, int}> */
	public static function validNumericBinds() : iterable{
		yield 'IPv4 loopback' => ['tcp://127.0.0.1:0', '127.0.0.1', FILTER_FLAG_IPV4];
		yield 'IPv4 wildcard' => ['tcp://0.0.0.0:19132', '0.0.0.0', FILTER_FLAG_IPV4];
		yield 'IPv6 loopback' => ['tcp://[::1]:0', '::1', FILTER_FLAG_IPV6];
		yield 'unassigned IPv6' => ['tcp://[2001:db8::1]:19132', '2001:db8::1', FILTER_FLAG_IPV6];
		yield 'IPv4-mapped IPv6' => ['tcp://[::ffff:127.0.0.1]:0', '::ffff:127.0.0.1', FILTER_FLAG_IPV6];
		yield 'maximum port' => ['tcp://127.0.0.1:65535', '127.0.0.1', FILTER_FLAG_IPV4];
	}

	#[DataProvider('validNumericBinds')]
	public function testValidNumericAuthorityReachesBind(string $bind, string $ip, int $family) : void{
		self::assertSame($ip, filter_var($ip, FILTER_VALIDATE_IP, $family));
		try{
			$server = new HttpServer(new TransportConfig(), $this->http, $bind);
		}catch(\InvalidArgumentException $e){
			self::fail('Valid numeric authority rejected before bind: ' . $e->getMessage());
		}catch(\RuntimeException $e){
			self::assertStringStartsWith('HTTP listener bind failed (', $e->getMessage());
			return;
		}
		self::assertNotSame('', $server->getAddress());
		$server->stop();
		self::assertSame(0, $server->getConnectionCount());
	}

	/** @return iterable<string, array{string}> */
	public static function ipv6Loopbacks() : iterable{
		yield 'IPv6' => ['tcp://[::1]:0'];
		yield 'mapped IPv6' => ['tcp://[::ffff:127.0.0.1]:0'];
	}

	#[DataProvider('ipv6Loopbacks')]
	public function testRealIpv6PostRetainsSocketEndpoint(string $bind) : void{
		$probe = @stream_socket_server($bind, $code, $error);
		if($probe === false){ self::markTestSkipped('OS does not permit this IPv6 loopback bind'); }
		fclose($probe);
		$this->server->stop();
		$this->transport->stop();
		$this->make(bind: $bind);
		$socket = $this->client();
		$local = stream_socket_get_name($socket, false);
		self::assertNotFalse($local);
		$this->send($socket, $this->post($this->fixture->offer(FakePeer::SDP)));
		self::assertStringStartsWith('HTTP/1.1 200 OK', $this->response($socket));
		$this->transport->poll();
		$connection = $this->listener->connections[1];
		self::assertInstanceOf(SignalingPeerConnection::class, $connection);
		$address = $connection->getSignalingPeerAddress();
		self::assertNotNull($address);
		self::assertSame($bind === 'tcp://[::1]:0' ? '::1' : '::ffff:127.0.0.1', $address->ip);
		self::assertSame((int) substr($local, strrpos($local, ':') + 1), $address->port);
	}

	#[DataProvider('ipv6Loopbacks')]
	public function testRealIpv6LoopbackWhenOsAllowsBind(string $bind) : void{
		$probe = @stream_socket_server($bind, $code, $error);
		if($probe === false){
			try{ new HttpServer(new TransportConfig(), $this->http, $bind); self::fail('OS bind failure not propagated'); }
			catch(\RuntimeException $e){ self::assertStringStartsWith('HTTP listener bind failed (', $e->getMessage()); }
			return;
		}
		fclose($probe);
		$this->server->stop();
		$this->transport->stop();
		$config = new TransportConfig();
		$this->http = new HttpSignaling($config, static fn() => new ServerMetadata('IPv6', 0, 'test', 'World', 0, 20, 0), $this->listener);
		$this->transport = new Transport($config, new ClientServerIdentityHandler($this->fixture->verifier(), $this->fixture->server, $config), $this->http, fn() : WebRtcPeer => $this->peer);
		$this->http->bind($this->transport);
		$this->server = new HttpServer($config, $this->http, $bind);
		$socket = $this->client();
		$this->send($socket, "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
		self::assertStringStartsWith('HTTP/1.1 200 OK', $this->response($socket));
		self::assertSame(0, $this->server->getConnectionCount());
		$this->server->stop();
		$this->server->stop();
	}

	public function testRealBackpressureResumesAndDoesNotStarveOtherClients() : void{
		$this->server->stop();
		$this->transport->stop();
		$this->make(new TransportConfig(maxSdpBytes: 16_777_216), 65536, fn() => $this->now);
		$this->peer->open = false;
		$this->peer->localSdp = FakePeer::SDP . 'a=x:' . str_repeat('z', 8_388_608) . "\r\n";
		$slow = $this->client();
		$this->send($slow, $this->post($this->fixture->offer(FakePeer::SDP)));
		for($i = 0; $i < 1024; ++$i){
			$this->transport->poll();
			$this->server->poll();
		}
		self::assertSame(HttpState::WRITING, $this->http->getState(1));
		self::assertSame(1, $this->server->getConnectionCount());
		self::assertLessThan(16_777_216 + 512, $this->server->getBufferedBytes());
		$valid = $this->client();
		$this->send($valid, "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
		self::assertStringStartsWith('HTTP/1.1 200 OK', $this->response($valid));
		self::assertSame(HttpState::WRITING, $this->http->getState(1));
		$response = $this->response($slow, 15);
		[, $answer] = explode("\r\n\r\n", $response, 2);
		self::assertSame($this->listener->answers[1], $answer);
		self::assertSame(1, substr_count($response, 'HTTP/1.1'));
		self::assertSame(0, $this->server->getConnectionCount());
		self::assertSame(0, $this->server->getBufferedBytes());
	}

	/** @return iterable<string, array{string, int}> */
	public static function maliciousRequests() : iterable{
		yield 'bare LF' => ["GET /v1/join HTTP/1.1\nHost: test\n\n", 400];
		yield 'duplicate length' => ["GET /v1/join HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n", 400];
		yield 'smuggling' => ["GET /v1/join HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n", 400];
		yield 'pipelining' => [str_repeat("GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n", 2), 400];
		yield 'method' => ["PUT /v1/join HTTP/1.1\r\nHost: test\r\n\r\n", 405];
		yield 'large header' => ["GET /v1/join HTTP/1.1\r\nHost: test\r\nX: " . str_repeat('x', 300) . "\r\n\r\n", 431];
		yield 'large body' => ["POST /v1/join/id HTTP/1.1\r\nHost: test\r\nContent-Type: application/sdp\r\nContent-Length: 1025\r\n\r\n", 413];
		yield 'large id' => ["POST /v1/join/123456789 HTTP/1.1\r\nHost: test\r\nContent-Type: application/sdp\r\nContent-Length: 1\r\n\r\nx", 414];
		yield 'body overrun' => ["POST /v1/join/id HTTP/1.1\r\nHost: test\r\nContent-Type: application/sdp\r\nContent-Length: 1\r\n\r\nxx", 400];
		yield 'identity absent' => ["POST /v1/join/id HTTP/1.1\r\nHost: test\r\nContent-Type: application/sdp\r\nContent-Length: " . strlen(FakePeer::SDP) . "\r\n\r\n" . FakePeer::SDP, 403];
		yield 'expect' => ["POST /v1/join/id HTTP/1.1\r\nHost: test\r\nExpect: 100-continue\r\n\r\n", 417];
	}

	#[DataProvider('maliciousRequests')]
	public function testAdversarialRequestsOverRealTcp(string $request, int $status) : void{
		$this->server->stop();
		$this->transport->stop();
		$this->make(new TransportConfig(maxHttpHeaderBytes: 256, maxSdpBytes: 1024, maxNetworkIdBytes: 8));
		$socket = $this->client();
		$this->send($socket, $request);
		$response = $this->response($socket);
		self::assertStringStartsWith('HTTP/1.1 ' . $status . ' ', $response);
		self::assertSame(1, substr_count($response, 'HTTP/1.1'));
		self::assertSame(0, $this->server->getConnectionCount());
		self::assertSame(0, $this->server->getBufferedBytes());
		self::assertSame([], $this->listener->connections);
	}

	public function testPhysicalAdmissionLimitAndShutdownRecoverAllSlots() : void{
		$this->server->stop();
		$this->transport->stop();
		$this->make(new TransportConfig(maxHttpConnections: 2));
		$first = $this->client();
		$second = $this->client();
		$this->server->poll();
		self::assertSame(2, $this->server->getConnectionCount());
		$excess = $this->client();
		self::assertSame('', $this->response($excess));
		self::assertSame(2, $this->server->getConnectionCount());
		stream_socket_shutdown($first, STREAM_SHUT_WR);
		self::assertStringStartsWith('HTTP/1.1 400 Bad Request', $this->response($first));
		$valid = $this->client();
		$this->send($valid, "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
		self::assertStringStartsWith('HTTP/1.1 200 OK', $this->response($valid));
		self::assertSame(1, $this->server->getConnectionCount());
		$this->server->stop();
		$this->server->stop();
		self::assertSame(0, $this->server->getConnectionCount());
		self::assertSame(HttpState::CLOSED, $this->http->getState(2));
		self::assertSame('', $this->response($second));
	}

	public function testOneAddressCannotHoldEveryHttpSlot() : void{
		$this->server->stop();
		$this->transport->stop();
		$this->make(new TransportConfig(maxHttpConnections: 8, maxHttpConnectionsPerIp: 2));
		$first = $this->client();
		$this->client();
		$this->server->poll();
		self::assertSame(2, $this->server->getConnectionCount());
		self::assertSame('', $this->response($this->client()));
		self::assertSame(2, $this->server->getConnectionCount());
		stream_socket_shutdown($first, STREAM_SHUT_WR);
		self::assertStringStartsWith('HTTP/1.1 400 Bad Request', $this->response($first));
		$valid = $this->client();
		$this->send($valid, "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
		self::assertStringStartsWith('HTTP/1.1 200 OK', $this->response($valid));
	}

	public function testRejectedAddressIsClosedBeforeSignaling() : void{
		$this->server->stop();
		$this->transport->stop();
		$seen = [];
		$allow = false;
		$this->make(admit: static function(string $ip) use (&$seen, &$allow) : bool{
			$seen[] = $ip;
			return $allow;
		});
		self::assertSame('', $this->response($this->client()));
		self::assertSame(['127.0.0.1'], $seen);
		self::assertSame(0, $this->server->getConnectionCount());
		self::assertSame(HttpState::CLOSED, $this->http->getState(1));
		$allow = true;
		$valid = $this->client();
		$this->send($valid, "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
		self::assertStringStartsWith('HTTP/1.1 200 OK', $this->response($valid));
	}

	public function testPendingNegotiationLimitAndShutdownCancellation() : void{
		$this->server->stop();
		$this->transport->stop();
		$this->make(new TransportConfig(maxPendingNegotiations: 1));
		$this->peer->gathered = false;
		$first = $this->client();
		$this->send($first, $this->post($this->fixture->offer(FakePeer::SDP)));
		for($i = 0; $i < 100 && $this->http->getState(1) !== HttpState::PENDING; ++$i){ $this->server->poll(1000); }
		$this->transport->poll();
		$second = $this->client();
		$this->send($second, $this->post($this->fixture->offer(FakePeer::SDP)));
		self::assertStringStartsWith('HTTP/1.1 503 Service Unavailable', $this->response($second));
		self::assertSame(HttpState::PENDING, $this->http->getState(1));
		$this->server->stop();
		self::assertSame(1, $this->peer->closes);
		self::assertSame(HttpState::CLOSED, $this->http->getState(1));
		self::assertSame([], $this->listener->connections);
	}

	public function testMetadataCanStopHostReentrantlyWithoutUsingClosedStreams() : void{
		$this->server->stop();
		$this->transport->stop();
		$this->make(metadata: function() : ServerMetadata{
			$this->server->stop();
			return new ServerMetadata('Server', 12, 'custom', 'World', 0, 20, 0);
		});
		$socket = $this->client();
		$this->send($socket, "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
		self::assertSame('', $this->response($socket));
		self::assertSame(0, $this->server->getConnectionCount());
	}

	public function testConsumerAnswerExceptionRejectsOnlyPeerAndHttpRemainsUsable() : void{
		$this->peer->open = false;
		$socket = $this->client();
		$this->send($socket, $this->post($this->fixture->offer(FakePeer::SDP)));
		$this->listener->answered = static function(int $id) : void{ throw new \RuntimeException('consumer failed'); };
		self::assertStringStartsWith('HTTP/1.1 500 ', $this->response($socket));
		self::assertSame('callback_error', $this->listener->closed[0][1]);
		self::assertCount(1, $this->listener->closed);
		$healthy = $this->client();
		$this->send($healthy, "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
		self::assertStringStartsWith('HTTP/1.1 200 ', $this->response($healthy));
		$this->server->stop();
		self::assertSame(1, $this->peer->closes);
		self::assertSame(0, $this->server->getConnectionCount());
	}

	public function testBindFailureAndIdlePollWaitAreExplicit() : void{
		$started = hrtime(true);
		$this->server->poll(10000);
		self::assertGreaterThanOrEqual(5_000_000, hrtime(true) - $started);
		self::assertLessThan(1_000_000_000, hrtime(true) - $started);
		$this->expectException(\RuntimeException::class);
		$this->expectExceptionMessage('HTTP listener bind failed');
		new HttpServer(new TransportConfig(), $this->http, 'tcp://192.0.2.1:0');
	}

	public function testInvalidClockAndReentrantPollingDoNotLeaveConnections() : void{
		$this->timed();
		$this->client();
		$this->server->poll();
		$this->now = NAN;
		try{ $this->server->poll(); self::fail('Nonfinite clock accepted'); }
		catch(\InvalidArgumentException){ self::assertSame(0, $this->server->getConnectionCount()); }
		$this->transport->stop();
		$this->make(metadata: function() : ServerMetadata{
			$this->server->poll();
			throw new \LogicException('unreachable');
		});
		$socket = $this->client();
		$this->send($socket, "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
		self::assertStringStartsWith('HTTP/1.1 500 Internal Server Error', $this->response($socket));
		self::assertSame(0, $this->server->getConnectionCount());
	}

	public function testRealBodyDeadlineExpiresWithoutAnotherTcpEvent() : void{
		$this->server->stop();
		$this->transport->stop();
		$this->make(new TransportConfig(signalingTimeoutSeconds: 1));
		$socket = $this->client();
		$this->send($socket, "POST /v1/join/id HTTP/1.1\r\nHost: test\r\nContent-Type: application/sdp\r\nContent-Length: 8\r\n\r\nv=");
		$start = hrtime(true);
		self::assertStringStartsWith('HTTP/1.1 408 Request Timeout', $this->response($socket));
		self::assertGreaterThan(500_000_000, hrtime(true) - $start);
		self::assertLessThan(2_000_000_000, hrtime(true) - $start);
	}

	public function testRealWriteDeadlineClosesNonReaderAndCancelsUndeliveredPeer() : void{
		$this->server->stop();
		$this->transport->stop();
		$this->make(new TransportConfig(maxSdpBytes: 16_777_216, signalingTimeoutSeconds: 1), 65536);
		$this->peer->open = false;
		$this->peer->localSdp = FakePeer::SDP . 'a=x:' . str_repeat('z', 8_388_608) . "\r\n";
		$socket = $this->client();
		$this->send($socket, $this->post($this->fixture->offer(FakePeer::SDP)));
		for($i = 0; $i < 100 && $this->http->getState(1) !== HttpState::WRITING; ++$i){
			$this->transport->poll();
			$this->server->poll(1000);
		}
		self::assertSame(HttpState::WRITING, $this->http->getState(1));
		self::assertGreaterThan(0, $this->server->getBufferedBytes());
		$start = hrtime(true);
		do{
			$this->transport->poll();
			$this->server->poll(10000);
		}while($this->server->getConnectionCount() !== 0 && hrtime(true) - $start < 2_000_000_000);
		self::assertSame(0, $this->server->getConnectionCount());
		self::assertSame(0, $this->server->getBufferedBytes());
		self::assertSame(1, $this->peer->closes);
		self::assertSame(HttpState::CLOSED, $this->http->getState(1));
		self::assertSame([], $this->listener->connections);
		self::assertGreaterThan(500_000_000, hrtime(true) - $start);
	}

	public function testTamperedFingerprintIsNotAdmittedOverTcp() : void{
		$body = str_replace(FakePeer::DIGEST, str_repeat('AC:', 31) . 'AC', $this->fixture->offer(FakePeer::SDP));
		$socket = $this->client();
		$this->send($socket, $this->post($body));
		$response = $this->response($socket);
		self::assertStringStartsWith('HTTP/1.1 403 Forbidden', $response);
		self::assertNull($this->peer->remoteSdp);
		self::assertSame([], $this->listener->answers);
		self::assertStringNotContainsString('a=identity', $response);
	}

	public function testCloningCannotDuplicateSocketOwnership() : void{
		$this->expectException(\Error::class);
		(clone $this->server)->stop();
	}

	/** @return iterable<string, array{int}> */
	public static function invalidIoBudgets() : iterable{
		yield 'zero' => [0];
		yield 'negative' => [-1];
		yield 'too large' => [1048577];
	}

	#[DataProvider('invalidIoBudgets')]
	public function testInvalidIoBudgetDoesNotOpenListener(int $bytes) : void{
		$this->expectException(\InvalidArgumentException::class);
		new HttpServer(new TransportConfig(), $this->http, ioBytes: $bytes);
	}

	public function testInvalidWaitBudgetDoesNotEnterPollLoop() : void{
		foreach([-1, 10001] as $wait){
			try{ $this->server->poll($wait); self::fail('Invalid wait accepted'); }
			catch(\InvalidArgumentException){ self::assertSame(0, $this->server->getConnectionCount()); }
		}
	}

	public function testOversizedLogicalResponseFailsClosedBeforeBuffering() : void{
		$this->peer->gathered = false;
		$socket = $this->client();
		$this->send($socket, $this->post($this->fixture->offer(FakePeer::SDP)));
		for($i = 0; $i < 100 && $this->http->getState(1) !== HttpState::PENDING; ++$i){ $this->server->poll(1000); }
		self::assertSame(HttpState::PENDING, $this->http->getState(1));
		$this->transport->poll();
		$this->http->onAnswer(1, str_repeat('x', 65537));
		try{ $this->server->poll(); self::fail('Oversized response buffered'); }
		catch(\RuntimeException $e){ self::assertSame('HTTP response exceeds bounded profile', $e->getMessage()); }
		self::assertSame(0, $this->server->getBufferedBytes());
		self::assertSame(0, $this->server->getConnectionCount());
		self::assertSame(HttpState::CLOSED, $this->http->getState(1));
		self::assertSame(1, $this->peer->closes);
	}

	public function testServesWhenDescriptorsExceedSelectSetSize() : void{
		if(PHP_OS_FAMILY === 'Windows' || !function_exists('posix_getrlimit')){ self::markTestSkipped('needs posix descriptor limits'); }
		$limits = posix_getrlimit();
		if($limits === false){ self::markTestSkipped('descriptor limits are unavailable'); }
		if(($limits['soft openfiles'] === 'unlimited' ? PHP_INT_MAX : $limits['soft openfiles']) < 2048){ self::markTestSkipped('soft descriptor limit is below 2048'); }
		$this->server->stop();
		$this->transport->stop();
		// select() only sees descriptors below 1024
		for($i = 0; $i < 1100; ++$i){
			$held = fopen('/dev/null', 'r');
			self::assertNotFalse($held);
			$this->sockets[] = $held;
		}
		$this->make();
		$socket = $this->client();
		fwrite($socket, "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
		self::assertStringStartsWith("HTTP/1.1 200 OK\r\n", $this->response($socket));
		self::assertSame(0, $this->server->getConnectionCount());
		// a blind poll still honours its wait
		$started = hrtime(true);
		$this->server->poll(10000);
		self::assertGreaterThanOrEqual(9_000_000, hrtime(true) - $started);
	}

	public function testTrustedProxyHeaderSetsThePlayerAddress() : void{
		$this->server->stop();
		$this->transport->stop();
		$seen = [];
		$this->make(new TransportConfig(maxHttpConnectionsPerIp: 1), admit: static function(string $ip) use (&$seen) : bool{ $seen[] = $ip; return $ip !== '198.51.100.66'; }, trustedProxies: ['127.0.0.0/8']);
		$get = "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n";
		// more than the per ip limit of 1 at once, all through the same proxy
		$first = $this->client();
		$second = $this->client();
		fwrite($first, "PROXY TCP4 203.0.113.9 10.0.0.1 51000 19132\r\n" . $get);
		fwrite($second, "\r\n\r\n\0\r\nQUIT\n\x21\x11\x00\x0c" . inet_pton('203.0.113.10') . inet_pton('10.0.0.1') . pack('nn', 51001, 19132));
		$this->server->poll(1000);
		fwrite($second, $get);
		self::assertStringStartsWith("HTTP/1.1 200 OK\r\n", $this->response($first));
		self::assertStringStartsWith("HTTP/1.1 200 OK\r\n", $this->response($second));
		self::assertSame(['203.0.113.9', '203.0.113.10'], $seen);
		// the admission check sees the player, not the proxy
		$banned = $this->client();
		fwrite($banned, "PROXY TCP4 198.51.100.66 10.0.0.1 51000 19132\r\n" . $get);
		self::assertSame('', $this->response($banned));
		// a trusted proxy that sends no header is not served
		$bare = $this->client();
		fwrite($bare, $get);
		self::assertSame('', $this->response($bare));
		self::assertSame(0, $this->server->getConnectionCount());
	}

	public function testUntrustedPeerCannotClaimAnAddress() : void{
		$this->server->stop();
		$this->transport->stop();
		$seen = [];
		$this->make(admit: static function(string $ip) use (&$seen) : bool{ $seen[] = $ip; return true; }, trustedProxies: ['10.9.9.9']);
		$socket = $this->client();
		fwrite($socket, "PROXY TCP4 203.0.113.9 10.0.0.1 51000 19132\r\nGET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
		self::assertStringStartsWith("HTTP/1.1 400 ", $this->response($socket));
		self::assertSame(['127.0.0.1'], $seen);
	}

	public function testSilentProxyConnectionTimesOut() : void{
		$this->server->stop();
		$this->transport->stop();
		$now = 0.0;
		$this->make(clock: static function() use (&$now) : float{ return $now; }, trustedProxies: ['127.0.0.1']);
		$socket = $this->client();
		fwrite($socket, 'PROXY TCP4 203.0.113.9');
		$this->server->poll(1000);
		$this->server->poll(1000);
		self::assertSame(1, $this->server->getConnectionCount());
		$now = 6.0;
		self::assertSame('', $this->response($socket));
		self::assertSame(0, $this->server->getConnectionCount());
	}

	/** @return array{string, string} */
	private function certificate(string $name = 'play.example.test', int $days = 30, ?\OpenSSLAsymmetricKey $signWith = null) : array{
		$config = ['config' => dirname(__DIR__) . '/identity/openssl.cnf'];
		$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'] + $config);
		self::assertNotFalse($key);
		$request = openssl_csr_new(['commonName' => $name], $key, $config);
		self::assertNotFalse($request);
		$certificate = openssl_csr_sign($request, null, $signWith ?? $key, $days, $config, random_int(1, PHP_INT_MAX));
		self::assertNotFalse($certificate);
		self::assertTrue(openssl_x509_export($certificate, $certificatePem));
		self::assertTrue(openssl_pkey_export($key, $keyPem, null, $config));
		$directory = sys_get_temp_dir() . '/nethernet-tls-' . bin2hex(random_bytes(6));
		mkdir($directory);
		file_put_contents($directory . '/cert.pem', $certificatePem);
		file_put_contents($directory . '/key.pem', $keyPem);
		$this->temporary[] = $directory;
		return [$directory . '/cert.pem', $directory . '/key.pem'];
	}

	/** @return resource */
	private function tlsClient(bool $expectFailure = false){
		$context = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false, 'capture_peer_cert' => true]]);
		$socket = stream_socket_client('tcp://' . $this->server->getAddress(), $code, $error, 1, STREAM_CLIENT_CONNECT, $context);
		self::assertNotFalse($socket);
		self::assertTrue(stream_set_blocking($socket, false));
		$this->sockets[] = $socket;
		$deadline = hrtime(true) + 3_000_000_000;
		do{
			$result = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT);
			$this->server->poll(1000);
		}while($result === 0 && hrtime(true) < $deadline);
		self::assertSame(!$expectFailure, $result === true);
		return $socket;
	}

	private const GET = "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n";

	public function testTlsAndPlainHttpShareThePort() : void{
		$this->server->stop();
		$this->transport->stop();
		[$certificate, $key] = $this->certificate();
		$tls = new TlsConfig($certificate, $key);
		self::assertSame(['play.example.test'], $tls->names);
		$this->make(tls: $tls);
		$secure = $this->tlsClient();
		$this->send($secure, self::GET);
		self::assertStringStartsWith("HTTP/1.1 200 OK\r\n", $this->response($secure));
		$plain = $this->client();
		fwrite($plain, self::GET);
		self::assertStringStartsWith("HTTP/1.1 200 OK\r\n", $this->response($plain));
		self::assertSame(0, $this->server->getConnectionCount());
		self::assertSame(['https' => 1, 'http' => 1, 'tlsRefused' => 0, 'tlsFailed' => 0], $this->server->getSchemeCounts());
	}

	public function testTlsHelloWithoutCertificateIsRefusedAtOnceAndCounted() : void{
		$socket = $this->client();
		fwrite($socket, "\x16\x03\x01\x00\x05hello");
		self::assertStringStartsWith("HTTP/1.1 400 ", $this->response($socket));
		self::assertSame(['https' => 0, 'http' => 0, 'tlsRefused' => 1, 'tlsFailed' => 0], $this->server->getSchemeCounts());
	}

	public function testRequiredTlsRefusesPlainHttpAndOldProtocols() : void{
		$this->server->stop();
		$this->transport->stop();
		[$certificate, $key] = $this->certificate();
		$this->make(tls: new TlsConfig($certificate, $key, true));
		$plain = $this->client();
		fwrite($plain, self::GET);
		self::assertSame('', $this->response($plain));
		$secure = $this->tlsClient();
		$this->send($secure, self::GET);
		self::assertStringStartsWith("HTTP/1.1 200 OK\r\n", $this->response($secure));
		// tls 1.1 and older are not offered
		$context = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false, 'security_level' => 0]]);
		$old = stream_socket_client('tcp://' . $this->server->getAddress(), $code, $error, 1, STREAM_CLIENT_CONNECT, $context);
		self::assertNotFalse($old);
		$this->sockets[] = $old;
		stream_set_blocking($old, false);
		$deadline = hrtime(true) + 3_000_000_000;
		do{
			$result = @stream_socket_enable_crypto($old, true, STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT);
			$this->server->poll(1000);
		}while($result === 0 && hrtime(true) < $deadline);
		self::assertNotTrue($result);
	}

	public function testBrokenAndStalledHandshakesAreDropped() : void{
		$this->server->stop();
		$this->transport->stop();
		$now = 0.0;
		[$certificate, $key] = $this->certificate();
		$this->make(clock: static function() use (&$now) : float{ return $now; }, tls: new TlsConfig($certificate, $key, now: time()));
		$garbage = $this->client();
		fwrite($garbage, "\x16\x03\x01\x00\x05hello");
		// at most a tls alert comes back, never http
		self::assertStringNotContainsString('HTTP/', $this->response($garbage));
		self::assertSame(0, $this->server->getConnectionCount());
		self::assertSame(1, $this->server->getSchemeCounts()['tlsFailed']);
		$stalled = $this->client();
		fwrite($stalled, "\x16\x03\x01");
		$this->server->poll(1000);
		$this->server->poll(1000);
		self::assertSame(1, $this->server->getConnectionCount());
		$now = 6.0;
		$this->response($stalled);
		self::assertSame(0, $this->server->getConnectionCount());
	}

	public function testClientRejectingTheCertificateCountsAsFailedHandshake() : void{
		$this->server->stop();
		$this->transport->stop();
		$now = 0.0;
		[$certificate, $key] = $this->certificate();
		$this->make(clock: static function() use (&$now) : float{ return $now; }, tls: new TlsConfig($certificate, $key, now: time()));
		// a real client verifies the chain and walks away from a self-signed certificate
		$context = stream_context_create(['ssl' => ['verify_peer' => true, 'verify_peer_name' => true, 'peer_name' => 'play.example.test']]);
		$socket = stream_socket_client('tcp://' . $this->server->getAddress(), $code, $error, 1, STREAM_CLIENT_CONNECT, $context);
		self::assertNotFalse($socket);
		$this->sockets[] = $socket;
		stream_set_blocking($socket, false);
		$deadline = hrtime(true) + 3_000_000_000;
		do{
			$result = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT);
			$this->server->poll(1000);
		}while($result === 0 && hrtime(true) < $deadline);
		self::assertFalse($result);
		fclose($socket);
		for($i = 0; $i < 5; ++$i){ $this->server->poll(1000); }
		$now = 6.0;
		$this->server->poll(1000);
		self::assertSame(0, $this->server->getConnectionCount());
		self::assertSame(['https' => 0, 'http' => 0, 'tlsRefused' => 0, 'tlsFailed' => 1], $this->server->getSchemeCounts());
		// a stalled hello that times out is a failed handshake as well
		$stalled = $this->client();
		fwrite($stalled, "\x16\x03\x01");
		$this->server->poll(1000);
		$now = 12.0;
		$this->response($stalled);
		self::assertSame(2, $this->server->getSchemeCounts()['tlsFailed']);
		// some clients finish the handshake, check the certificate afterwards and leave without a request
		$checked = $this->tlsClient();
		fclose($checked);
		for($i = 0; $i < 5; ++$i){ $this->server->poll(1000); }
		$now = 100.0;
		$this->server->poll(1000);
		self::assertSame(0, $this->server->getConnectionCount());
		self::assertSame(['https' => 0, 'http' => 0, 'tlsRefused' => 0, 'tlsFailed' => 3], $this->server->getSchemeCounts());
	}

	public function testRenewedCertificateIsServedWithoutRestart() : void{
		$this->server->stop();
		$this->transport->stop();
		[$certificate, $key] = $this->certificate();
		$this->make(tls: new TlsConfig($certificate, $key));
		$fingerprint = function() : string{
			$socket = $this->tlsClient();
			$peer = stream_context_get_options($socket)['ssl']['peer_certificate'] ?? null;
			self::assertInstanceOf(\OpenSSLCertificate::class, $peer);
			$this->send($socket, self::GET);
			self::assertStringStartsWith("HTTP/1.1 200 OK\r\n", $this->response($socket));
			return (string) openssl_x509_fingerprint($peer, 'sha256');
		};
		$first = $fingerprint();
		[$renewedCertificate, $renewedKey] = $this->certificate();
		// same order a renewal tool would not guarantee, so swap both before the next handshake
		rename($renewedKey, $key);
		rename($renewedCertificate, $certificate);
		$second = $fingerprint();
		self::assertNotSame($first, $second);
	}

	public function testProxyHeaderIsReadBeforeTheTlsHandshake() : void{
		$this->server->stop();
		$this->transport->stop();
		$seen = [];
		[$certificate, $key] = $this->certificate();
		$this->make(admit: static function(string $ip) use (&$seen) : bool{ $seen[] = $ip; return true; }, trustedProxies: ['127.0.0.1'], tls: new TlsConfig($certificate, $key, true));
		$context = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]]);
		$socket = stream_socket_client('tcp://' . $this->server->getAddress(), $code, $error, 1, STREAM_CLIENT_CONNECT, $context);
		self::assertNotFalse($socket);
		$this->sockets[] = $socket;
		fwrite($socket, "PROXY TCP4 203.0.113.9 10.0.0.1 51000 19132\r\n");
		stream_set_blocking($socket, false);
		$deadline = hrtime(true) + 3_000_000_000;
		do{
			$result = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT);
			$this->server->poll(1000);
		}while($result === 0 && hrtime(true) < $deadline);
		self::assertTrue($result);
		$this->send($socket, self::GET);
		self::assertStringStartsWith("HTTP/1.1 200 OK\r\n", $this->response($socket));
		self::assertSame(['203.0.113.9'], $seen);
	}

	public function testTlsConfigRejectsUnusableMaterial() : void{
		[$certificate, $key] = $this->certificate();
		[, $otherKey] = $this->certificate();
		foreach([
			'mismatched key' => fn() => new TlsConfig($certificate, $otherKey),
			'missing file' => fn() => new TlsConfig($certificate . '.missing', $key),
			'key as certificate' => fn() => new TlsConfig($key, $key),
			'expired' => fn() => new TlsConfig($certificate, $key, now: time() + 40 * 86400),
			'not valid yet' => fn() => new TlsConfig($certificate, $key, now: time() - 86400),
			'stream wrapper' => fn() => new TlsConfig('file://' . $certificate, $key)
		] as $case => $construct){
			try{ $construct(); self::fail('accepted ' . $case); }catch(\InvalidArgumentException){ $this->addToAssertionCount(1); }
		}
		self::assertGreaterThan(time(), (new TlsConfig($certificate, $key))->expiresAt);
	}
}
