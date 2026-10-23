<?php

declare(strict_types=1);

namespace amber\nethernet\tests\transport;

use amber\nethernet\backend\WebRtcPeer;
use amber\nethernet\Channel;
use amber\nethernet\Connection;
use amber\nethernet\ConnectionState;
use amber\nethernet\identity\ClientServerIdentityHandler;
use amber\nethernet\identity\IdentityHandler;
use amber\nethernet\identity\PeerIdentity;
use amber\nethernet\identity\SdpIdentity;
use amber\nethernet\SendResult;
use amber\nethernet\tests\identity\IdentityFixture;
use amber\nethernet\Transport;
use amber\nethernet\TransportConfig;
use amber\nethernet\TransportException;
use PHPUnit\Framework\TestCase;

final class TransportTest extends TestCase{
	private IdentityFixture $fixture;
	private RecordingListener $listener;
	private FakePeer $peer;
	private float $now = 0.0;
	private Transport $transport;

	protected function setUp() : void{
		$this->fixture = new IdentityFixture();
		$this->listener = new RecordingListener();
		$this->peer = new FakePeer();
		$this->transport = $this->makeTransport();
	}

	protected function tearDown() : void{ $this->transport->stop(); }

	private function makeTransport(?TransportConfig $config = null, ?IdentityHandler $handler = null, ?\Closure $factory = null) : Transport{
		return new Transport($config ?? new TransportConfig(), $handler ?? new ClientServerIdentityHandler($this->fixture->verifier(), $this->fixture->server, clock: fn() => 1000), $this->listener, $factory ?? fn() : WebRtcPeer => $this->peer, fn() => $this->now, fn() => 1000);
	}

	private function open() : Connection{
		$id = $this->transport->accept('opaque-network-id', $this->fixture->offer(FakePeer::SDP));
		for($i = 0; $i < 3; ++$i){ $this->transport->poll(); }
		return $this->listener->connections[$id];
	}

	public function testAnswerThenAuthenticatedOpenAndNoDuplicateEvents() : void{
		$connection = $this->open();
		self::assertSame(['answer', 'open'], $this->listener->events);
		self::assertSame('player', $connection->getIdentity()->subject);
		self::assertSame('opaque-network-id', $connection->getNetworkId());
		self::assertSame(ConnectionState::OPEN, $connection->getState());
		self::assertStringNotContainsString('a=identity:', $this->peer->remoteSdp ?? '');
		$parsed = SdpIdentity::fromSdp($this->listener->answers[$connection->getId()], new TransportConfig());
		self::assertSame('operator.test', $parsed->providerDomain);
		$this->transport->poll();
		self::assertSame(['answer', 'open'], $this->listener->events);
		$connection->close();
		$connection->close();
		self::assertSame(['answer', 'open', 'close'], $this->listener->events);
		self::assertSame(1, $this->peer->closes);
	}

	public function testReliableFragmentOrderAndAcceptanceAfterLocalSend() : void{
		$connection = $this->open();
		$accepted = new \stdClass();
		$accepted->values = [];
		self::assertSame(SendResult::ACCEPTED, $connection->send('abcdefghijk', accepted: function(bool $ok) use ($accepted) : void{ $accepted->values[] = $ok; }));
		self::assertSame([], $accepted->values);
		$connection->send('last');
		$this->transport->poll();
		self::assertSame([[Channel::RELIABLE, "\1abcdefg"], [Channel::RELIABLE, "\0hijk"], [Channel::RELIABLE, "\0last"]], $this->peer->sent);
		self::assertSame([true], $accepted->values);
	}

	public function testBackpressureAndCloseCancelQueuedCallbacksOnce() : void{
		$this->transport = $this->makeTransport(new TransportConfig(maxPayloadBytes: 10, maxOutgoingQueueBytes: 10, maxOutgoingQueueMessages: 1));
		$connection = $this->open();
		$this->peer->blocked = true;
		$accepted = new \stdClass();
		$accepted->values = [];
		$callback = function(bool $ok) use ($accepted) : void{ $accepted->values[] = $ok; };
		self::assertSame(SendResult::ACCEPTED, $connection->send('1234567890', accepted: $callback));
		self::assertSame(SendResult::BACKPRESSURE, $connection->send('', accepted: $callback));
		self::assertSame(SendResult::DROPPED, $connection->send('abc', Channel::UNRELIABLE, accepted: $callback));
		$this->transport->poll();
		self::assertSame([false, false], $accepted->values);
		$connection->close();
		self::assertSame([false, false, false], $accepted->values);
		self::assertSame([], $this->peer->sent);
	}

	public function testReceiveFragmentAssemblyAndUnreliableBinaryPayload() : void{
		$this->open();
		$this->peer->incoming = ['RELIABLE' => ["\1abcdefg", "\0hijk"], 'UNRELIABLE' => ["\0\xff\0"]];
		$this->transport->poll();
		self::assertCount(2, $this->listener->payloads);
		self::assertContains([1, 'abcdefghijk', Channel::RELIABLE], $this->listener->payloads);
		self::assertContains([1, "\xff\0", Channel::UNRELIABLE], $this->listener->payloads);
	}

	public function testFingerprintMismatchNeverOpens() : void{
		$this->peer->fingerprint = str_replace('AB', 'CD', FakePeer::DIGEST);
		$this->transport->accept('id', $this->fixture->offer(FakePeer::SDP));
		for($i = 0; $i < 4; ++$i){ $this->transport->poll(); }
		self::assertSame(['answer', 'close'], $this->listener->events);
		self::assertSame('identity_fingerprint_mismatch', $this->listener->closed[0][1]);
		self::assertSame(1, $this->peer->closes);
	}

	public function testGatheringTimeoutClosesPeerWithoutAnswer() : void{
		$this->peer->gathered = false;
		$this->transport->accept('id', $this->fixture->offer(FakePeer::SDP));
		$this->transport->poll();
		$this->now = 15.0;
		$this->transport->poll();
		self::assertSame(['close'], $this->listener->events);
		self::assertSame('signaling_timeout', $this->listener->closed[0][1]);
	}

	public function testAssemblyTimeoutResetsAndCloses() : void{
		$connection = $this->open();
		$this->peer->incoming['RELIABLE'] = ["\1abc"];
		$this->transport->poll();
		$this->now = 10.0;
		$this->transport->poll();
		self::assertSame(ConnectionState::CLOSED, $connection->getState());
		self::assertSame('framing_invalid', $this->listener->closed[0][1]);
	}

	public function testCloseInAnswerCallbackPreventsOpen() : void{
		$this->listener->answered = fn(int $id) => $this->transport->close($id);
		$this->transport->accept('id', $this->fixture->offer(FakePeer::SDP));
		for($i = 0; $i < 4; ++$i){ $this->transport->poll(); }
		self::assertSame(['answer', 'close'], $this->listener->events);
	}

	public function testLateDuplicateVerificationAndCancellationAreHarmless() : void{
		$handler = new DeferredIdentityHandler($this->fixture->server);
		$this->transport = $this->makeTransport(handler: $handler);
		$id = $this->transport->accept('id', $this->fixture->offer(FakePeer::SDP));
		$this->transport->close($id);
		$handler->complete(new PeerIdentity('late', ''), null);
		$handler->complete(null, new TransportException('late', 'late'));
		$this->transport->poll();
		self::assertSame(1, $handler->cancels);
		self::assertSame(['close'], $this->listener->events);
		self::assertSame(0, $this->peer->closes);
	}

	public function testFirstVerificationCompletionWinsAndNoInlineBackendWork() : void{
		$handler = new DeferredIdentityHandler($this->fixture->server);
		$this->transport = $this->makeTransport(handler: $handler);
		$this->transport->accept('id', $this->fixture->offer(FakePeer::SDP));
		$handler->complete(new PeerIdentity('first', ''), null);
		$handler->complete(null, new TransportException('duplicate', 'duplicate'));
		self::assertNull($this->peer->remoteSdp);
		for($i = 0; $i < 3; ++$i){ $this->transport->poll(); }
		self::assertSame('first', $this->listener->connections[1]->getIdentity()->subject);
		self::assertSame(0, $handler->cancels);
	}

	public function testOversizedSendDoesNotDestroyAnAuthenticatedConnection() : void{
		$this->transport = $this->makeTransport(new TransportConfig(maxPayloadBytes: 10));
		$connection = $this->open();
		self::assertSame(SendResult::DROPPED, $connection->send('12345678901'));
		self::assertSame(ConnectionState::OPEN, $connection->getState());
		self::assertSame(SendResult::ACCEPTED, $connection->send('valid'));
	}

	public function testOversizedIncomingFrameClosesEvenWhenWorkBudgetCannotFitIt() : void{
		$this->transport = $this->makeTransport(new TransportConfig(maxMessageBytes: 8, maxReceiveQueueBytes: 8, maxSendQueueBytes: 8, peerPollBytes: 8, globalPollBytes: 8));
		$connection = $this->open();
		$this->peer->incoming['RELIABLE'] = [str_repeat('x', 9)];
		$this->transport->poll();
		self::assertSame(ConnectionState::CLOSED, $connection->getState());
		self::assertSame('framing_invalid', $this->listener->closed[0][1]);
	}

	public function testPeerAndGlobalWorkBudgetsRotateBetweenConnections() : void{
		$config = new TransportConfig(maxMessageBytes: 8, maxReceiveQueueBytes: 8, maxSendQueueBytes: 8, peerPollMessages: 1, globalPollMessages: 1);
		$other = new FakePeer();
		$peers = [$this->peer, $other];
		$index = 0;
		$this->transport = $this->makeTransport($config, factory: function() use ($peers, &$index) : WebRtcPeer{ return $peers[$index++]; });
		$offer = $this->fixture->offer(FakePeer::SDP);
		$this->transport->accept('first', $offer);
		$this->transport->accept('second', $offer);
		for($i = 0; $i < 3; ++$i){ $this->transport->poll(); }
		$this->listener->connections[1]->send('one');
		$this->listener->connections[1]->send('two');
		$this->listener->connections[2]->send('other');
		$this->transport->poll();
		$this->transport->poll();
		self::assertCount(1, $this->peer->sent);
		self::assertCount(1, $other->sent);
		$this->transport->poll();
		self::assertCount(2, $this->peer->sent);
	}

	public function testGlobalMemoryReservationIsReleasedByClose() : void{
		$other = new FakePeer();
		$peers = [$this->peer, $other];
		$index = 0;
		$this->transport = $this->makeTransport(new TransportConfig(maxPayloadBytes: 10, maxAggregateBytes: 10), factory: function() use ($peers, &$index) : WebRtcPeer{ return $peers[$index++]; });
		$offer = $this->fixture->offer(FakePeer::SDP);
		$this->transport->accept('one', $offer);
		$this->transport->accept('two', $offer);
		for($i = 0; $i < 3; ++$i){ $this->transport->poll(); }
		$one = $this->listener->connections[1];
		$two = $this->listener->connections[2];
		self::assertSame(SendResult::ACCEPTED, $one->send('1234567890'));
		self::assertSame(SendResult::BACKPRESSURE, $two->send('x'));
		$one->close();
		self::assertSame(SendResult::ACCEPTED, $two->send('1234567890'));
	}

	public function testCloseAnotherPeerFromListenerDoesNotAccessRemovedEntry() : void{
		$other = new FakePeer();
		$peers = [$this->peer, $other];
		$index = 0;
		$this->transport = $this->makeTransport(factory: function() use ($peers, &$index) : WebRtcPeer{ return $peers[$index++]; });
		$offer = $this->fixture->offer(FakePeer::SDP);
		$this->transport->accept('one', $offer);
		$this->transport->accept('two', $offer);
		$this->listener->opened = function(Connection $connection) : void{ $this->transport->close($connection->getId() === 1 ? 2 : 1); };
		for($i = 0; $i < 3; ++$i){ $this->transport->poll(); }
		self::assertCount(1, $this->listener->connections);
		self::assertCount(1, $this->listener->closed);
	}

	public function testFinalSignedAnswerMustFitSdpLimit() : void{
		$offer = $this->fixture->offer(FakePeer::SDP);
		$this->peer->localSdp = FakePeer::SDP . 'a=unknown:' . str_repeat('x', strlen($offer)) . "\r\n";
		$this->transport = $this->makeTransport(new TransportConfig(maxSdpBytes: strlen($this->peer->localSdp) + 1));
		$this->transport->accept('id', $offer);
		$this->transport->poll();
		$this->transport->poll();
		self::assertSame(['close'], $this->listener->events);
		self::assertSame('invalid_sdp', $this->listener->closed[0][1]);
	}

	public function testReceiveProgressIsNotStarvedByContinuousOutgoingTraffic() : void{
		$this->transport = $this->makeTransport(new TransportConfig(peerPollMessages: 1, globalPollMessages: 1));
		$connection = $this->open();
		$this->peer->incoming['RELIABLE'] = ["\0in"];
		for($i = 0; $i < 4; ++$i){
			$connection->send('out');
			$this->transport->poll();
		}
		self::assertCount(1, $this->listener->payloads);
	}

	public function testCallbackReentryClosesWithoutCompletingAnotherSendTwice() : void{
		$connection = $this->open();
		$results = new \stdClass();
		$results->values = [];
		$connection->send('one', accepted: function(bool $ok) use ($connection, $results) : void{
			$results->values[] = $ok;
			$connection->close();
		});
		$connection->send('two', accepted: function(bool $ok) use ($results) : void{ $results->values[] = $ok; });
		$this->transport->poll();
		self::assertSame([true, false], $results->values);
		self::assertCount(1, $this->peer->sent);
	}

	public function testDroppingTransportClosesRetainedConnection() : void{
		$peer = new FakePeer();
		$listener = new RecordingListener();
		$transport = new Transport(new TransportConfig(), new ClientServerIdentityHandler($this->fixture->verifier(), $this->fixture->server, clock: static fn() => 1000), $listener, static fn() => $peer, static fn() => 0.0, static fn() => 1000);
		$transport->accept('id', $this->fixture->offer(FakePeer::SDP));
		for($i = 0; $i < 3; ++$i){ $transport->poll(); }
		$connection = $listener->connections[1];
		unset($transport);
		self::assertSame(ConnectionState::CLOSED, $connection->getState());
		self::assertSame(1, $peer->closes);
	}

	public function testPendingVerifierIsCancelledWhenTransportIsReleased() : void{
		$handler = new DeferredIdentityHandler($this->fixture->server);
		$transport = new Transport(new TransportConfig(), $handler, new RecordingListener());
		$transport->accept('id', $this->fixture->offer(FakePeer::SDP));
		unset($transport);
		self::assertSame(1, $handler->cancels);
		$handler->complete(new PeerIdentity('late', ''), null);
	}

	public function testReentrantImmediateSendDoesNotResetPeerBudgetTwice() : void{
		$other = new FakePeer();
		$peers = [$this->peer, $other];
		$index = 0;
		$this->transport = $this->makeTransport(new TransportConfig(peerPollMessages: 1), factory: function() use ($peers, &$index) : WebRtcPeer{ return $peers[$index++]; });
		$offer = $this->fixture->offer(FakePeer::SDP);
		$this->transport->accept('one', $offer);
		$this->transport->accept('two', $offer);
		for($i = 0; $i < 4; ++$i){ $this->transport->poll(); }
		$two = $this->listener->connections[2];
		$this->peer->incoming['RELIABLE'] = ["\0x"];
		$this->listener->received = function(Connection $connection) use ($two) : void{
			$two->send('one', immediate: true);
			$two->send('two');
		};
		$this->transport->poll();
		$firstFrames = $other->sent;
		self::assertCount(1, $firstFrames);
		$this->transport->poll();
		self::assertCount(2, $other->sent);
	}

	public function testCloseStillCompletesAllCallbacksAndNotifiesWhenConsumerThrows() : void{
		$connection = $this->open();
		$results = new \stdClass();
		$results->values = [];
		$connection->send('one', accepted: static function(bool $ok) : void{ throw new \LogicException('consumer'); });
		$connection->send('two', accepted: function(bool $ok) use ($results) : void{ $results->values[] = $ok; });
		$connection->close();
		self::assertSame([false], $results->values);
		self::assertSame(ConnectionState::CLOSED, $connection->getState());
		self::assertCount(1, $this->listener->closed);
		self::assertSame('callback_error', $this->listener->closed[0][1]);
		self::assertSame(1, $this->peer->closes);
	}

	public function testNativeSendFailureCancelsWholeMessageAndClosesOnce() : void{
		$connection = $this->open();
		$results = new \stdClass();
		$results->values = [];
		$connection->send('abcdefghijk', accepted: function(bool $ok) use ($results) : void{ $results->values[] = $ok; });
		$this->peer->failure = new TransportException('native_send_failed', 'failed');
		$this->transport->poll();
		self::assertSame([false], $results->values);
		self::assertSame('native_send_failed', $this->listener->closed[0][1]);
		self::assertSame(1, $this->peer->closes);
	}

	public function testReceiveGlobalMemoryOverflowClosesAndReleasesAssembly() : void{
		$this->transport = $this->makeTransport(new TransportConfig(maxPayloadBytes: 10, maxAggregateBytes: 10));
		$connection = $this->open();
		$connection->send('1234567890');
		$this->peer->blocked = true;
		$this->peer->incoming['RELIABLE'] = ["\1x"];
		$this->transport->poll();
		self::assertSame(ConnectionState::CLOSED, $connection->getState());
		self::assertSame('memory_limit', $this->listener->closed[0][1]);
	}

	public function testVerificationAndConnectionTimeoutsAreTerminal() : void{
		$handler = new DeferredIdentityHandler($this->fixture->server);
		$this->transport = $this->makeTransport(handler: $handler);
		$this->transport->accept('id', $this->fixture->offer(FakePeer::SDP));
		$this->now = 15.0;
		$this->transport->poll();
		self::assertSame(1, $handler->cancels);
		self::assertSame('signaling_timeout', $this->listener->closed[0][1]);
		$this->transport = $this->makeTransport();
		$this->peer->open = false;
		$this->transport->accept('id', $this->fixture->offer(FakePeer::SDP));
		$this->transport->poll();
		$this->transport->poll();
		$this->now = 30.0;
		$this->transport->poll();
		self::assertSame('connect_timeout', $this->listener->closed[1][1]);
	}

	public function testMalformedOfferAndPendingLimitNeverAllocatePeer() : void{
		$this->transport = $this->makeTransport(new TransportConfig(maxPendingNegotiations: 1), new DeferredIdentityHandler($this->fixture->server));
		try{ $this->transport->accept('id', FakePeer::SDP); self::fail('Unsigned offer admitted'); }catch(TransportException $error){ self::assertSame('identity_missing', $error->errorCode); }
		$offer = $this->fixture->offer(FakePeer::SDP);
		$this->transport->accept('one', $offer);
		try{ $this->transport->accept('two', $offer); self::fail('Limit ignored'); }catch(TransportException $error){ self::assertSame('connection_limit', $error->errorCode); }
		self::assertNull($this->peer->remoteSdp);
	}

	public function testCancelledPayloadIsReleasedBeforeReentrantCallback() : void{
		$size = 8 * 1024 * 1024;
		$this->peer->capacity = 65536;
		$this->transport = $this->makeTransport(new TransportConfig(maxPayloadBytes: $size, maxOutgoingQueueBytes: $size, maxAggregateBytes: $size));
		$connection = $this->open();
		$baseline = memory_get_usage();
		$observed = new \stdClass();
		$observed->bytes = 0;
		$connection->send(str_repeat('x', $size), accepted: function(bool $ok) use ($observed) : void{ $observed->bytes = memory_get_usage(); });
		$connection->close();
		self::assertLessThan($baseline + 1024 * 1024, $observed->bytes);
	}

	public function testGlobalBudgetRotationDoesNotLockEachPeerToOneDirection() : void{
		$other = new FakePeer();
		$peers = [$this->peer, $other];
		$index = 0;
		$this->transport = $this->makeTransport(new TransportConfig(globalPollMessages: 1), factory: function() use ($peers, &$index) : WebRtcPeer{ return $peers[$index++]; });
		$offer = $this->fixture->offer(FakePeer::SDP);
		$this->transport->accept('one', $offer);
		$this->transport->accept('two', $offer);
		for($i = 0; $i < 3; ++$i){ $this->transport->poll(); }
		$this->peer->incoming['RELIABLE'] = ["\0x"];
		$other->incoming['RELIABLE'] = ["\0y"];
		for($i = 0; $i < 8; ++$i){
			$this->listener->connections[1]->send('out');
			$this->listener->connections[2]->send('out');
			$this->transport->poll();
		}
		self::assertCount(2, $this->listener->payloads);
		self::assertNotEmpty($this->peer->sent);
		self::assertNotEmpty($other->sent);
	}
}
