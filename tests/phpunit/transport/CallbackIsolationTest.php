<?php

declare(strict_types=1);

namespace amber\nethernet\tests\transport;

use amber\nethernet\backend\WebRtcPeer;
use amber\nethernet\Channel;
use amber\nethernet\Connection;
use amber\nethernet\ConnectionState;
use amber\nethernet\identity\ClientServerIdentityHandler;
use amber\nethernet\identity\IdentityHandler;
use amber\nethernet\internal\TransportBudget;
use amber\nethernet\SendResult;
use amber\nethernet\tests\identity\IdentityFixture;
use amber\nethernet\Transport;
use amber\nethernet\TransportConfig;
use amber\nethernet\TransportException;
use PHPUnit\Framework\TestCase;

final class CallbackIsolationTest extends TestCase{
	private Transport $transport;
	private RecordingListener $listener;
	private FakePeer $first;
	private FakePeer $second;
	private IdentityFixture $fixture;

	protected function setUp() : void{
		$this->fixture = new IdentityFixture();
		$this->listener = new RecordingListener();
		$this->first = new FakePeer();
		$this->second = new FakePeer();
		$peers = [$this->first, $this->second];
		$index = 0;
		$this->transport = new Transport(new TransportConfig(), new ClientServerIdentityHandler($this->fixture->verifier(), $this->fixture->server, clock: static fn() => 1000), $this->listener, static function() use ($peers, &$index) : WebRtcPeer{ return $peers[$index++]; }, static fn() => 0.0, static fn() => 1000);
	}

	protected function tearDown() : void{ $this->transport->stop(); }

	/** @return array{Connection, Connection} */
	private function open() : array{
		$offer = $this->fixture->offer(FakePeer::SDP);
		$this->transport->accept('first', $offer);
		$this->transport->accept('second', $offer);
		for($i = 0; $i < 3; ++$i){ $this->transport->poll(); }
		return [$this->listener->connections[1], $this->listener->connections[2]];
	}

	private function assertReleased() : void{
		$budget = (new \ReflectionProperty(Transport::class, 'budget'))->getValue($this->transport);
		self::assertInstanceOf(TransportBudget::class, $budget);
		self::assertSame(0, (new \ReflectionProperty(TransportBudget::class, 'reserved'))->getValue($budget));
	}

	public function testThrowingSuccessClosesOnlyOwnerDrainsOnceAndNeverRetriesDeliveredFrames() : void{
		[$a, $b] = $this->open();
		$results = [];
		$a->send('one', accepted: static function(bool $ok) use (&$results) : void{ $results[] = $ok; throw new \LogicException('consumer callback fault'); });
		$a->send('two', accepted: static function(bool $ok) use (&$results) : void{ $results[] = $ok; });
		$b->send('healthy');
		$this->transport->poll();
		$this->transport->poll();
		$a->close();
		self::assertSame([true, false], $results);
		self::assertSame(ConnectionState::CLOSED, $a->getState());
		self::assertSame(ConnectionState::OPEN, $b->getState());
		self::assertSame([[Channel::RELIABLE, "\0one"]], $this->first->sent);
		self::assertSame([[Channel::RELIABLE, "\0healthy"]], $this->second->sent);
		self::assertSame('callback_error', $this->listener->closed[0][1]);
		self::assertCount(1, $this->listener->closed);
		self::assertSame(1, $this->first->closes);
		$this->assertReleased();
	}

	/** @return iterable<string, array{bool}> */
	public static function closeTargets() : iterable{ yield 'self' => [true]; yield 'other' => [false]; }

	#[\PHPUnit\Framework\Attributes\DataProvider('closeTargets')]
	public function testSuccessMayCloseEitherConnectionWithoutLateWork(bool $self) : void{
		[$a, $b] = $this->open();
		$results = [];
		$a->send('one', accepted: static function(bool $ok) use ($a, $b, $self, &$results) : void{ $results[] = $ok; ($self ? $a : $b)->close(); });
		$a->send('two', accepted: static function(bool $ok) use (&$results) : void{ $results[] = $ok; });
		$this->transport->poll();
		self::assertSame($self ? [true, false] : [true, true], $results);
		self::assertSame(ConnectionState::CLOSED, ($self ? $a : $b)->getState());
		self::assertCount(1, $this->listener->closed);
		$this->assertReleased();
	}

	public function testThrowingCancellationStillDrainsAllClosuresAndReleasesAssemblies() : void{
		[$a, $b] = $this->open();
		$this->first->incoming['RELIABLE'] = ["\1partial"];
		$this->transport->poll();
		$values = [];
		$a->send('queued', accepted: static function(bool $ok) use ($a, &$values) : void{ $values[] = $ok; $a->close(); throw new \LogicException('cancel fault'); });
		$a->send('more', accepted: static function(bool $ok) use (&$values) : void{ $values[] = $ok; });
		$a->close();
		$a->close();
		self::assertSame([false, false], $values);
		self::assertSame(ConnectionState::OPEN, $b->getState());
		self::assertCount(1, $this->listener->closed);
		self::assertSame('callback_error', $this->listener->closed[0][1]);
		$this->assertReleased();
	}

	/** @return iterable<string, array{string}> */
	public static function sendModes() : iterable{ foreach(['immediate', 'unreliable', 'oversized', 'backpressure', 'closed'] as $mode){ yield $mode => [$mode]; } }

	#[\PHPUnit\Framework\Attributes\DataProvider('sendModes')]
	public function testSynchronousCompletionsUseSameIsolationPolicy(string $mode) : void{
		[$a, $b] = $this->open();
		if($mode === 'closed'){ $a->close(); }
		if($mode === 'backpressure'){ $this->first->blocked = true; for($i = 0; $i < 256; ++$i){ $a->send(''); } }
		$calls = 0;
		$result = $a->send($mode === 'oversized' ? str_repeat('x', 8 * 1024 * 1024 + 1) : 'x', $mode === 'unreliable' ? Channel::UNRELIABLE : Channel::RELIABLE, true, static function(bool $ok) use (&$calls) : void{ ++$calls; throw new \LogicException('sync fault'); });
		self::assertSame(match($mode){ 'closed', 'oversized' => SendResult::DROPPED, 'backpressure' => SendResult::BACKPRESSURE, default => SendResult::ACCEPTED }, $result);
		self::assertSame(1, $calls);
		self::assertSame(ConnectionState::CLOSED, $a->getState());
		self::assertSame(ConnectionState::OPEN, $b->getState());
		self::assertCount(1, $this->listener->closed);
		$this->assertReleased();
	}

	/** @return iterable<string, array{string}> */
	public static function listenerEvents() : iterable{ foreach(['answer', 'open', 'payload'] as $event){ yield $event => [$event]; } }

	#[\PHPUnit\Framework\Attributes\DataProvider('listenerEvents')]
	public function testListenerFaultIsConfinedToItsPeer(string $event) : void{
		$fault = static function(int $id) : void{ if($id === 1){ throw new \LogicException('listener fault'); } };
		if($event === 'answer'){ $this->listener->answered = $fault; }
		if($event === 'open'){ $this->listener->opened = static function(Connection $c) use ($fault) : void{ $fault($c->getId()); }; }
		if($event === 'payload'){ $this->listener->received = static function(Connection $c) use ($fault) : void{ $fault($c->getId()); }; }
		$offer = $this->fixture->offer(FakePeer::SDP);
		$this->transport->accept('first', $offer); $this->transport->accept('second', $offer);
		for($i = 0; $i < 3; ++$i){ $this->transport->poll(); }
		if($event === 'payload'){ $this->first->incoming['RELIABLE'] = ["\0bad"]; $this->transport->poll(); }
		self::assertSame(ConnectionState::OPEN, $this->listener->connections[2]->getState());
		self::assertCount(1, $this->listener->closed);
		self::assertSame('callback_error', $this->listener->closed[0][1]);
		$this->assertReleased();
	}

	public function testNativeSendErrorKeepsNativeCodeAndOtherPeerProgresses() : void{
		[$a, $b] = $this->open();
		$values = [];
		$this->first->failure = new TransportException('native_send_failed', 'native fault');
		$a->send('broken', accepted: static function(bool $ok) use (&$values) : void{ $values[] = $ok; throw new \LogicException('consumer fault too'); });
		$b->send('good');
		$this->transport->poll();
		self::assertSame([false], $values);
		self::assertSame('native_send_failed', $this->listener->closed[0][1]);
		self::assertCount(1, $this->second->sent);
		$this->assertReleased();
	}

	public function testCloseListenerFaultIsReportedWithoutRecursiveClose() : void{
		[$a, $b] = $this->open();
		$log = tempnam(sys_get_temp_dir(), 'nethernet-callback-');
		self::assertIsString($log);
		$previous = ini_set('error_log', $log);
		try{
			$this->listener->closing = static function(int $id) use ($a) : void{ if($id === 1){ $a->close(); throw new \LogicException('secret must not be logged'); } };
			$a->close();
			$this->transport->poll();
			self::assertSame(ConnectionState::OPEN, $b->getState());
			self::assertCount(1, $this->listener->closed);
			$diagnostic = file_get_contents($log);
			self::assertIsString($diagnostic);
			self::assertStringContainsString('LogicException', $diagnostic);
			self::assertStringNotContainsString('secret', $diagnostic);
			$this->assertReleased();
		}finally{ ini_set('error_log', (string) $previous); unlink($log); }
	}

	public function testNativeCleanupFailurePropagatesAfterAllCallbacksAndNotification() : void{
		[$a, $b] = $this->open();
		$native = new TransportException('native_close_failed', 'native cleanup fault');
		$this->first->closeFailure = $native;
		$values = [];
		$a->send('queued', accepted: static function(bool $ok) use (&$values) : void{ $values[] = $ok; throw new \LogicException('cancel fault'); });
		try{ $a->close(); self::fail('Native cleanup error was hidden'); }catch(\amber\nethernet\internal\TransportCleanupException $e){ self::assertSame($native, $e->getPrevious()); }
		self::assertSame([false], $values);
		self::assertSame(ConnectionState::CLOSED, $a->getState());
		self::assertSame(ConnectionState::OPEN, $b->getState());
		self::assertCount(1, $this->listener->closed);
		$a->close();
		self::assertSame(1, $this->first->closes);
		$this->assertReleased();
	}

	public function testThrowingVerifierCancellationIsTerminalAndLateCompletionCannotResurrect() : void{
		$handler = $this->createMock(IdentityHandler::class);
		$complete = null;
		$cancels = 0;
		$handler->method('verifyClient')->willReturnCallback(static function(string $token, string $fingerprints, string $jws, \Closure $callback) use (&$complete, &$cancels) : \Closure{
			$complete = $callback;
			return static function() use (&$cancels) : void{ ++$cancels; throw new \LogicException('verifier cancel fault'); };
		});
		$transport = new Transport(new TransportConfig(), $handler, $this->listener, static fn() => throw new \LogicException('Must not allocate backend'), static fn() => 0.0);
		$id = $transport->accept('pending', $this->fixture->offer(FakePeer::SDP));
		$transport->close($id);
		self::assertInstanceOf(\Closure::class, $complete);
		$complete(new \amber\nethernet\identity\PeerIdentity('late', ''), null);
		$transport->poll(); $transport->close($id); $transport->stop();
		self::assertSame(1, $cancels);
		self::assertCount(1, $this->listener->closed);
		self::assertSame('callback_error', $this->listener->closed[0][1]);
		self::assertSame([], $this->listener->connections);
	}

	public function testInternalTransportInvariantIsNotCaughtAsConsumerFault() : void{
		$this->open();
		$budget = (new \ReflectionProperty(Transport::class, 'budget'))->getValue($this->transport);
		self::assertInstanceOf(TransportBudget::class, $budget);
		(new \ReflectionProperty(TransportBudget::class, 'generation'))->setValue($budget, PHP_INT_MAX);
		try{ $this->transport->poll(); self::fail('Internal invariant was hidden'); }catch(\LogicException $e){ self::assertSame('Transport poll generation exhausted', $e->getMessage()); }
		self::assertSame([], $this->listener->closed);
	}

	#[\PHPUnit\Framework\Attributes\DataProvider('closeTargets')]
	public function testReentrantNativeCleanupErrorIsNotMisclassifiedAsConsumerFault(bool $self) : void{
		[$a, $b] = $this->open();
		$peer = $self ? $this->first : $this->second;
		$peer->closeFailure = new TransportException('native_close_failed', 'native fault');
		$a->send('delivered', accepted: static function(bool $ok) use ($a, $b, $self) : void{ ($self ? $a : $b)->close(); });
		try{ $this->transport->poll(); self::fail('Reentrant native cleanup error was hidden'); }
		catch(\amber\nethernet\internal\TransportCleanupException $e){ self::assertSame($peer->closeFailure, $e->getPrevious()); }
		self::assertSame(ConnectionState::CLOSED, ($self ? $a : $b)->getState());
		self::assertSame(1, $peer->closes);
		self::assertCount(1, $this->listener->closed);
		$this->assertReleased();
	}
}
