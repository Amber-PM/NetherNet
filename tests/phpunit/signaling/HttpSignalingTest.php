<?php

declare(strict_types=1);

namespace amber\nethernet\tests\signaling;

use amber\nethernet\backend\WebRtcPeer;
use amber\nethernet\Channel;
use amber\nethernet\ConnectionState;
use amber\nethernet\SignalingPeerAddress;
use amber\nethernet\SignalingPeerConnection;
use amber\nethernet\identity\ClientServerIdentityHandler;
use amber\nethernet\identity\IdentityHandler;
use amber\nethernet\identity\SdpIdentity;
use amber\nethernet\signaling\HttpException;
use amber\nethernet\signaling\HttpSignaling;
use amber\nethernet\signaling\HttpState;
use amber\nethernet\signaling\ServerMetadata;
use amber\nethernet\tests\identity\IdentityFixture;
use amber\nethernet\tests\transport\DeferredIdentityHandler;
use amber\nethernet\tests\transport\FakePeer;
use amber\nethernet\tests\transport\RecordingListener;
use amber\nethernet\Transport;
use amber\nethernet\TransportConfig;
use amber\nethernet\TransportException;
use amber\nethernet\TransportListener;
use PHPUnit\Framework\TestCase;

final class HttpSignalingTest extends TestCase{
	private IdentityFixture $fixture;
	private RecordingListener $listener;
	private HttpSignaling $http;
	private Transport $transport;
	private FakePeer $peer;
	private float $now = 0.0;

	protected function setUp() : void{
		$this->fixture = new IdentityFixture();
		$this->listener = new RecordingListener();
		$this->peer = new FakePeer();
		$this->make();
	}

	protected function tearDown() : void{ $this->transport->stop(); }

	/** @param \Closure(): ServerMetadata|null $metadata */
	private function make(?TransportConfig $config = null, ?IdentityHandler $handler = null, ?\Closure $metadata = null) : void{
		$config ??= new TransportConfig();
		$this->http = new HttpSignaling($config, $metadata ?? static fn() => new ServerMetadata('Server', 12, 'custom', 'World', 0, 20, 0), $this->listener);
		$this->transport = new Transport($config, $handler ?? new ClientServerIdentityHandler($this->fixture->verifier(), $this->fixture->server, $config, fn() => 1000), $this->http, fn() : WebRtcPeer => $this->peer, fn() => $this->now, fn() => 1000);
		$this->http->bind($this->transport);
	}

	private function post(?string $body = null, string $id = 'opaque') : int{
		$body ??= $this->fixture->offer(FakePeer::SDP);
		$exchange = $this->http->open();
		$this->http->receive($exchange, "POST /v1/join/$id HTTP/1.1\r\nHost: test\r\nContent-Type: application/sdp\r\nContent-Length: " . strlen($body) . "\r\n\r\n" . $body);
		return $exchange;
	}

	public function testGetAndDistinctTransportIdWithSignedAnswer() : void{
		$get = $this->http->open();
		$this->http->receive($get, "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
		$response = $this->http->takeResponse($get);
		self::assertNotNull($response);
		self::assertSame(200, $response->status);
		self::assertSame('{"name":"Server","protocol":12,"version":"custom","level":"World","players":0,"maxPlayers":20,"gameType":0}', $response->body);
		$this->http->finish($get);
		$post = $this->post(id: 'opaque%3Aid');
		self::assertSame(2, $post);
		self::assertSame(1, $this->http->getTransportId($post));
		$this->assertPending($post);
		$this->transport->poll();
		$this->assertPending($post);
		$this->transport->poll();
		$response = $this->http->takeResponse($post);
		self::assertNotNull($response);
		self::assertSame('application/sdp', $response->contentType);
		self::assertSame($this->listener->answers[1], $response->body);
		$answer = SdpIdentity::fromSdp($response->body, new TransportConfig());
		self::assertSame('operator.test', $answer->providerDomain);
		AnswerSignatures::verify($answer);
		self::assertSame([], $this->listener->connections);
		self::assertNull($this->http->takeResponse($post));
		$this->http->finish($post);
		$this->transport->poll();
		self::assertSame('opaque:id', $this->listener->connections[1]->getNetworkId());
		self::assertSame(HttpState::CLOSED, $this->http->getState($post));
	}

	private function assertPending(int $id) : void{
		self::assertSame(HttpState::PENDING, $this->http->getState($id));
		self::assertNull($this->http->takeResponse($id));
	}

	public function testDirectAdmissionKeepsAddressOptional() : void{
		$id = $this->transport->accept('192.0.2.1', $this->fixture->offer(FakePeer::SDP));
		for($i = 0; $i < 3; ++$i){ $this->transport->poll(); }
		$connection = $this->listener->connections[$id];
		self::assertInstanceOf(SignalingPeerConnection::class, $connection);
		self::assertNull($connection->getSignalingPeerAddress());
	}

	public function testCancelledExchangeReleasesAddressBeforeAndAfterAdmission() : void{
		foreach([false, true] as $admit){
			$address = new SignalingPeerAddress('192.0.2.123', 54321);
			$reference = \WeakReference::create($address);
			$id = $this->http->open($address);
			unset($address);
			if($admit){
				$body = $this->fixture->offer(FakePeer::SDP);
				$this->http->receive($id, "POST /v1/join/id HTTP/1.1\r\nHost: test\r\nContent-Type: application/sdp\r\nContent-Length: " . strlen($body) . "\r\n\r\n" . $body);
				self::assertNotNull($this->http->getTransportId($id));
			}
			self::assertNotNull($reference->get());
			$this->http->cancel($id);
			self::assertSame(HttpState::CLOSED, $this->http->getState($id));
			self::assertNull($reference->get());
		}
		$this->transport->poll();
		self::assertSame([], $this->listener->connections);
	}

	public function testCancelPendingAndIgnoreLateAnswers() : void{
		$pending = $this->post();
		$id = $this->http->getTransportId($pending);
		self::assertNotNull($id);
		$this->transport->poll();
		$this->http->cancel($pending);
		$this->http->cancel($pending);
		$this->http->onAnswer($id, 'late');
		self::assertNull($this->http->takeResponse($pending));
		self::assertSame(HttpState::CLOSED, $this->http->getState($pending));
		self::assertSame(1, $this->peer->closes);
	}

	public function testCancelAfterOpenDoesNotClosePeer() : void{
		$post = $this->post();
		for($i = 0; $i < 3; ++$i){ $this->transport->poll(); }
		$this->http->cancel($post);
		self::assertSame(ConnectionState::OPEN, $this->listener->connections[1]->getState());
		self::assertSame(0, $this->peer->closes);
	}

	public function testUndeliveredAnswerCancelsConnectingPeer() : void{
		$post = $this->post();
		$this->transport->poll();
		$this->transport->poll();
		self::assertNotNull($this->http->takeResponse($post));
		$this->http->cancel($post);
		self::assertSame(1, $this->peer->closes);
	}

	public function testAuthFailureMissingIdentityAndInternalFailureAreSafe() : void{
		$post = $this->post($this->fixture->offer(FakePeer::SDP, 1));
		$this->transport->poll();
		self::assertSame(403, $this->http->takeResponse($post)?->status);
		$this->http->finish($post);
		$post = $this->post(FakePeer::SDP);
		self::assertSame(403, $this->http->takeResponse($post)?->status);
		$this->http->finish($post);
		$this->peer->localSdp = 'secret backend broken';
		$post = $this->post();
		$this->transport->poll();
		$this->transport->poll();
		$response = $this->http->takeResponse($post);
		self::assertNotNull($response);
		self::assertSame(500, $response->status);
		self::assertSame('Internal Server Error', $response->body);
	}

	public function testTimeoutEventsAndTransportTimeout() : void{
		$read = $this->http->open();
		$this->http->timeout($read);
		self::assertSame(408, $this->http->takeResponse($read)?->status);
		$post = $this->post();
		$this->http->timeout($post);
		self::assertSame(504, $this->http->takeResponse($post)?->status);
		$post = $this->post();
		$this->now = 15.0;
		$this->transport->poll();
		self::assertSame(504, $this->http->takeResponse($post)?->status);
	}

	public function testDuplicateAnswersAndListenerExceptionsDoNotRepeatResponse() : void{
		$post = $this->post();
		$this->listener->answered = static function(int $id) : void{ throw new \RuntimeException('consumer secret'); };
		$this->transport->poll();
		try{ $this->transport->poll(); self::fail('Expected consumer exception'); }catch(\RuntimeException $e){ self::assertSame('consumer secret', $e->getMessage()); }
		$this->http->onAnswer(1, 'duplicate');
		$response = $this->http->takeResponse($post);
		self::assertNotNull($response);
		self::assertSame(200, $response->status);
		self::assertStringStartsWith('v=0', $response->body);
		self::assertNull($this->http->takeResponse($post));
		$this->http->cancel($post);
	}

	public function testExtraInputCancelsPendingAndCannotSendSecondResponse() : void{
		$post = $this->post();
		$this->http->receive($post, 'X');
		self::assertSame(400, $this->http->takeResponse($post)?->status);
		$this->http->receive($post, 'X');
		self::assertNull($this->http->takeResponse($post));
		self::assertSame(HttpState::CLOSED, $this->http->getState($post));
	}

	public function testIndependentPendingRequestsReleaseSlots() : void{
		$this->make(new TransportConfig(maxHttpConnections: 2, maxPendingNegotiations: 1));
		$first = $this->post();
		$second = $this->post();
		self::assertSame(503, $this->http->takeResponse($second)?->status);
		try{ $this->http->open(); self::fail('Expected limit'); }catch(HttpException $e){ self::assertSame(503, $e->status); }
		$this->http->finish($second);
		$this->http->cancel($first);
		$third = $this->post();
		self::assertSame(HttpState::PENDING, $this->http->getState($third));
	}

	public function testMetadataFailureAndReentrantCancellation() : void{
		$this->make(metadata: static function() : ServerMetadata{ throw new \RuntimeException('metadata secret'); });
		$get = $this->http->open();
		$this->http->receive($get, "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
		self::assertSame('Internal Server Error', $this->http->takeResponse($get)?->body);
		$this->http->finish($get);
		$get = 1;
		$this->make(metadata: function() use (&$get) : ServerMetadata{
			$this->http->cancel($get);
			return new ServerMetadata('s', 1, 'v', 'l', 0, 1, 0);
		});
		$get = $this->http->open();
		$this->http->receive($get, "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
		self::assertNull($this->http->takeResponse($get));
	}

	public function testMetadataReentryCannotResurrectTakenResponse() : void{
		$id = 0;
		$this->make(metadata: function() use (&$id) : ServerMetadata{
			$this->http->timeout($id);
			self::assertSame(408, $this->http->takeResponse($id)?->status);
			return new ServerMetadata('s', 1, 'v', 'l', 0, 1, 0);
		});
		$id = $this->http->open();
		$this->http->receive($id, "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
		self::assertSame(HttpState::WRITING, $this->http->getState($id));
		self::assertNull($this->http->takeResponse($id));
		$this->http->finish($id);
	}

	public function testEofAndFinishBeforeResponse() : void{
		$id = $this->http->open();
		$this->http->receive($id, "GET /v1/join HTTP/1.1\r\nHost:");
		$this->http->eof($id);
		self::assertSame(400, $this->http->takeResponse($id)?->status);
		$this->http->finish($id);
		$id = $this->post();
		$this->expectException(\LogicException::class);
		$this->http->finish($id);
	}

	public function testAdmissionTimeoutReentryCannotLeaveNegotiationAlive() : void{
		$base = new ClientServerIdentityHandler($this->fixture->verifier(), $this->fixture->server, clock: fn() => 1000);
		$exchange = 0;
		$handler = new class($base, function() use (&$exchange) : void{ $this->http->timeout($exchange); }) implements IdentityHandler{
			/** @param \Closure(): void $before */
			public function __construct(private readonly IdentityHandler $base, private readonly \Closure $before){}
			public function verifyClient(string $token, string $canonicalFingerprints, string $detachedJws, \Closure $complete) : \Closure{
				($this->before)();
				return $this->base->verifyClient($token, $canonicalFingerprints, $detachedJws, $complete);
			}
			public function signServer(string $canonicalFingerprints, int $now) : string{ return $this->base->signServer($canonicalFingerprints, $now); }
		};
		$this->make(handler: $handler);
		$exchange = $this->http->open();
		$offer = $this->fixture->offer(FakePeer::SDP);
		$this->http->receive($exchange, "POST /v1/join/id HTTP/1.1\r\nHost: test\r\nContent-Type: application/sdp\r\nContent-Length: " . strlen($offer) . "\r\n\r\n" . $offer);
		self::assertSame(504, $this->http->takeResponse($exchange)?->status);
		self::assertNull($this->http->getTransportId($exchange));
		$this->http->finish($exchange);
		for($i = 0; $i < 3; ++$i){ $this->transport->poll(); }
		self::assertSame([], $this->listener->answers);
		self::assertSame([], $this->listener->connections);
	}

	public function testDeferredVerificationCompletionAfterCancelUsesRealIdentity() : void{
		$handler = new DeferredIdentityHandler($this->fixture->server);
		$this->make(handler: $handler);
		$offer = $this->fixture->offer(FakePeer::SDP);
		$identity = $this->fixture->verifier()->verify(SdpIdentity::fromSdp($offer, new TransportConfig()), 1000);
		$post = $this->post($offer);
		$this->http->cancel($post);
		$handler->complete($identity, null);
		$handler->complete($identity, null);
		$this->transport->poll();
		self::assertSame(1, $handler->cancels);
		self::assertSame([], $this->listener->answers);
		self::assertSame([], $this->listener->connections);
		self::assertNull($this->http->takeResponse($post));
	}

	public function testConcurrentRequestsRouteAnswersExclusivelyAndReleaseBoth() : void{
		$config = new TransportConfig();
		$http = new HttpSignaling($config, static fn() => new ServerMetadata('s', 1, 'v', 'l', 0, 1, 0), $this->listener);
		$peers = [new FakePeer(), new FakePeer()];
		$cursor = 0;
		$this->transport = new Transport($config, new ClientServerIdentityHandler($this->fixture->verifier(), $this->fixture->server, clock: fn() => 1000), $http, function() use ($peers, &$cursor) : WebRtcPeer{ return $peers[$cursor++]; }, fn() => 0.0, fn() => 1000);
		$this->http = $http;
		$http->bind($this->transport);
		$one = $this->post(id: 'one');
		$two = $this->post(id: 'two');
		for($i = 0; $i < 2; ++$i){ $this->transport->poll(); }
		self::assertSame($this->listener->answers[1], $http->takeResponse($one)?->body);
		self::assertSame($this->listener->answers[2], $http->takeResponse($two)?->body);
		$http->cancel($one);
		$http->finish($two);
		$this->transport->poll();
		self::assertArrayNotHasKey(1, $this->listener->connections);
		self::assertSame('two', $this->listener->connections[2]->getNetworkId());
	}

	public function testStopCleansEverySlotEvenIfCloseListenerThrows() : void{
		$config = new TransportConfig();
		$listener = $this->createMock(TransportListener::class);
		$listener->method('onClose')->willThrowException(new \RuntimeException('trusted consumer failure'));
		$this->http = new HttpSignaling($config, static fn() => new ServerMetadata('s', 1, 'v', 'l', 0, 1, 0), $listener);
		$this->transport = new Transport($config, new ClientServerIdentityHandler($this->fixture->verifier(), $this->fixture->server, clock: fn() => 1000), $this->http, fn() : WebRtcPeer => new FakePeer());
		$this->http->bind($this->transport);
		$one = $this->post();
		$two = $this->post();
		try{ $this->http->stop(); self::fail('Expected consumer exception'); }catch(\RuntimeException $e){ self::assertSame('trusted consumer failure', $e->getMessage()); }
		self::assertSame(HttpState::CLOSED, $this->http->getState($one));
		self::assertSame(HttpState::CLOSED, $this->http->getState($two));
		$this->http->stop();
		$this->transport->stop();
	}

	public function testPayloadIsForwardedAfterSuccessfulSignaling() : void{
		$post = $this->post();
		for($i = 0; $i < 3; ++$i){ $this->transport->poll(); }
		$this->peer->incoming = ['UNRELIABLE' => ["\0hello"]];
		$this->transport->poll();
		self::assertSame([[1, 'hello', Channel::UNRELIABLE]], $this->listener->payloads);
		self::assertNotNull($this->http->takeResponse($post));
		$this->http->finish($post);
		$this->http->stop();
		self::assertSame(ConnectionState::OPEN, $this->listener->connections[1]->getState());
	}

	public function testPeerFailureInvalidatesQueuedAnswerBeforeTakeResponse() : void{
		$this->make(new TransportConfig(maxHttpConnections: 1));
		$post = $this->post();
		$this->transport->poll();
		$this->transport->poll();
		self::assertSame(HttpState::RESPONSE, $this->http->getState($post));
		$this->peer->state = 'FAILED';
		$this->transport->poll();
		$response = $this->http->takeResponse($post);
		self::assertNotNull($response);
		self::assertSame(500, $response->status);
		self::assertSame('Internal Server Error', $response->body);
		self::assertSame('text/plain; charset=utf-8', $response->contentType);
		self::assertNull($this->http->getTransportId($post));
		self::assertSame(1, $this->peer->closes);
		self::assertCount(1, $this->listener->closed);
		$this->http->onClose(1, 'backend_failed', 'SECRET-JWT');
		$this->http->onAnswer(1, 'SECRET-SDP');
		self::assertNull($this->http->takeResponse($post));
		self::assertSame(500, $response->status);
		$this->http->finish($post);
		$this->http->cancel($post);
		$next = $this->http->open();
		self::assertSame(HttpState::HEADERS, $this->http->getState($next));
		$this->http->cancel($next);
	}

	public function testPeerFailureDuringWritingClosesExchangeWithoutReplacingResponse() : void{
		$post = $this->post();
		$this->transport->poll();
		$this->transport->poll();
		$response = $this->http->takeResponse($post);
		self::assertNotNull($response);
		self::assertSame(200, $response->status);
		$this->peer->state = 'FAILED';
		$this->transport->poll();
		self::assertSame(HttpState::CLOSED, $this->http->getState($post));
		self::assertNull($this->http->takeResponse($post));
		self::assertNull($this->http->getTransportId($post));
		self::assertSame(200, $response->status);
		self::assertSame(1, $this->peer->closes);
		$this->http->finish($post);
		$this->http->cancel($post);
	}

	public function testPeerFailureWhileGatheringNeverProducesAnswer() : void{
		$this->peer->gathered = false;
		$post = $this->post();
		$this->transport->poll();
		$this->peer->state = 'FAILED';
		$this->transport->poll();
		self::assertSame(500, $this->http->takeResponse($post)?->status);
		self::assertSame([], $this->listener->answers);
		self::assertSame(1, $this->peer->closes);
		$this->http->finish($post);
	}

	public function testPeerFailureAfterDeliveryIsOnlyATransportClose() : void{
		$post = $this->post();
		$this->transport->poll();
		$this->transport->poll();
		self::assertSame(200, $this->http->takeResponse($post)?->status);
		$this->http->finish($post);
		$this->transport->poll();
		$connection = $this->listener->connections[1];
		self::assertSame(ConnectionState::OPEN, $connection->getState());
		$this->peer->state = 'FAILED';
		$this->transport->poll();
		self::assertSame(ConnectionState::CLOSED, $connection->getState());
		self::assertSame(HttpState::CLOSED, $this->http->getState($post));
		self::assertNull($this->http->takeResponse($post));
		self::assertCount(1, $this->listener->closed);
		self::assertSame(1, $this->peer->closes);
	}

	public function testReentrantTransportCloseFromAnswerInvalidatesUnclaimedSuccess() : void{
		$post = $this->post();
		$this->listener->answered = function(int $id) : void{ $this->transport->close($id, 'SECRET-JWT'); };
		$this->transport->poll();
		$this->transport->poll();
		$response = $this->http->takeResponse($post);
		self::assertNotNull($response);
		self::assertSame(500, $response->status);
		self::assertStringNotContainsString('SECRET', $response->encode());
		self::assertSame(1, $this->peer->closes);
		self::assertSame([], $this->listener->connections);
		$this->http->finish($post);
	}

	public function testCloseListenerExceptionDoesNotLeaveStaleResponseOrPeer() : void{
		$config = new TransportConfig(maxHttpConnections: 1);
		$listener = $this->createMock(TransportListener::class);
		$listener->expects(self::once())->method('onClose')->willThrowException(new \RuntimeException('SECRET-CONSUMER'));
		$this->http = new HttpSignaling($config, static fn() => new ServerMetadata('s', 1, 'v', 'l', 0, 1, 0), $listener);
		$this->transport = new Transport($config, new ClientServerIdentityHandler($this->fixture->verifier(), $this->fixture->server, clock: fn() => 1000), $this->http, fn() : WebRtcPeer => $this->peer);
		$this->http->bind($this->transport);
		$post = $this->post();
		$this->transport->poll();
		$this->transport->poll();
		$this->peer->state = 'FAILED';
		try{ $this->transport->poll(); self::fail('Expected consumer exception'); }catch(\RuntimeException $e){ self::assertSame('SECRET-CONSUMER', $e->getMessage()); }
		$response = $this->http->takeResponse($post);
		self::assertNotNull($response);
		self::assertSame(500, $response->status);
		self::assertStringNotContainsString('SECRET', $response->encode());
		self::assertSame(1, $this->peer->closes);
		$this->http->finish($post);
		$this->transport->stop();
		$next = $this->http->open();
		$this->http->cancel($next);
	}
}
