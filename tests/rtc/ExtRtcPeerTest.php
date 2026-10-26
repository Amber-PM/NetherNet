<?php

declare(strict_types=1);

namespace amber\nethernet\tests\rtc;

use amber\nethernet\backend\ExtRtcPeer;
use amber\nethernet\Channel;
use amber\nethernet\TransportConfig;
use amber\nethernet\TransportException;
use amber\rtc\DataChannelOptions;
use amber\rtc\GatheringState;
use amber\rtc\PeerConnection;
use amber\rtc\PeerConnectionOptions;
use amber\rtc\RtcRuntime;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ExtRtcPeerTest extends TestCase{
	/** @var list<ExtRtcPeer> */
	private array $peers = [];

	protected function tearDown() : void{
		foreach($this->peers as $peer){
			$peer->close();
		}
		$this->peers = [];
		self::waitFor(static fn() => RtcRuntime::getStats()['activePeers'] === 0 && RtcRuntime::getStats()['activeChannels'] === 0);
	}

	/** @param \Closure(): bool $condition */
	public static function waitFor(\Closure $condition) : void{
		$deadline = hrtime(true) + 10_000_000_000;
		while(!$condition()){
			if(hrtime(true) >= $deadline){ self::fail('Native operation did not complete within ten seconds'); }
			usleep(1000);
		}
	}

	private function peer(?TransportConfig $config = null, int $begin = 0, int $end = 0, ?string $bind = null, bool $mux = false) : ExtRtcPeer{
		$peer = new ExtRtcPeer($config ?? new TransportConfig(), $begin, $end, $bind, $mux);
		$this->peers[] = $peer;
		return $peer;
	}

	/** @return array{ExtRtcPeer, ExtRtcPeer} */
	private function pair(?TransportConfig $offerConfig = null, ?TransportConfig $answerConfig = null) : array{
		$offer = $this->peer($offerConfig);
		$answer = $this->peer($answerConfig);
		self::connect($offer, $answer);
		return [$offer, $answer];
	}

	private static function connect(ExtRtcPeer $offer, ExtRtcPeer $answer) : void{
		$offer->createChannel(Channel::RELIABLE);
		$offer->createChannel(Channel::UNRELIABLE);
		self::waitFor(fn() => $offer->isGatheringComplete());
		$answer->setRemoteOffer($offer->getLocalDescription() ?? self::fail('Missing offer'));
		self::waitFor(fn() => $answer->isGatheringComplete());
		$offer->setRemoteAnswer($answer->getLocalDescription() ?? self::fail('Missing answer'));
		$adopted = [];
		self::waitFor(function() use ($offer, $answer, &$adopted) : bool{
			foreach($answer->pollChannels() as $channel){ $adopted[] = $channel; }
			return $offer->isChannelOpen(Channel::RELIABLE) && $offer->isChannelOpen(Channel::UNRELIABLE) &&
				$answer->isChannelOpen(Channel::RELIABLE) && $answer->isChannelOpen(Channel::UNRELIABLE);
		});
		self::assertEqualsCanonicalizing([Channel::RELIABLE, Channel::UNRELIABLE], $adopted);
	}

	private static function deliver(ExtRtcPeer $from, ExtRtcPeer $to, Channel $channel, string $payload) : void{
		self::assertTrue($from->sendFrame($channel, $payload));
		self::waitFor(fn() => $to->peekFrame($channel) !== null);
		self::assertSame($payload, $to->peekFrame($channel));
		self::assertSame($payload, $to->receiveFrame($channel));
		self::assertNull($to->peekFrame($channel));
	}

	public function testNegotiatesChannelsFingerprintsAndBinaryPayloads() : void{
		ExtRtcPeer::assertAvailable();
		[$offer, $answer] = $this->pair(new TransportConfig(maxMessageBytes: 512), new TransportConfig(maxMessageBytes: 512));
		self::assertSame('CONNECTED', $offer->getState());
		self::assertSame('CONNECTED', $answer->getState());
		self::assertNull($answer->getFailureState());
		$fingerprint = $answer->getRemoteFingerprint() ?? '';
		self::assertMatchesRegularExpression('/^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/', $fingerprint);
		self::assertStringContainsString('a=fingerprint:sha-256 ' . $fingerprint, $offer->getLocalDescription() ?? '');
		self::assertSame([], $answer->pollChannels());
		foreach([$offer, $answer] as $peer){
			foreach([Channel::RELIABLE, Channel::UNRELIABLE] as $channel){
				$info = $peer->getChannelInfo($channel);
				self::assertSame($channel === Channel::RELIABLE ? 'ReliableDataChannel' : 'UnreliableDataChannel', $info['label']);
				self::assertSame('', $info['protocol']);
				self::assertSame($channel === Channel::UNRELIABLE, $info['unordered']);
				self::assertSame($channel === Channel::UNRELIABLE ? 0 : null, $info['maxRetransmits']);
				self::assertNull($info['maxPacketLifeTime']);
				self::assertTrue($info['open']);
				self::assertFalse($info['closed']);
				self::assertSame(512, $peer->getMessageCapacity($channel));
			}
		}
		foreach([Channel::RELIABLE, Channel::UNRELIABLE] as $channel){
			foreach(["\x00\x01\xfe\xffhello\x00", '', str_repeat("\x00\xff", 256)] as $payload){
				self::deliver($offer, $answer, $channel, $payload);
				self::deliver($answer, $offer, $channel, $payload);
			}
		}
	}

	private static function advertisedMessageSize(ExtRtcPeer $peer) : string{
		preg_match_all('/^a=max-message-size:(\d+)\r?$/m', $peer->getLocalDescription() ?? '', $matches);
		self::assertCount(1, $matches[1]);
		return $matches[1][0];
	}

	public function testAdvertisedMessageSizeIsLocalLimitAndBothSidesUseMinimum() : void{
		[$offer, $answer] = $this->pair(new TransportConfig(maxMessageBytes: 1024), new TransportConfig(maxMessageBytes: 512));
		self::assertSame('1024', self::advertisedMessageSize($offer));
		self::assertSame('512', self::advertisedMessageSize($answer));
		$before = RtcRuntime::getStats()['sendRejectedCount'];
		foreach([Channel::RELIABLE, Channel::UNRELIABLE] as $channel){
			self::assertSame(512, $offer->getMessageCapacity($channel));
			self::assertSame(512, $answer->getMessageCapacity($channel));
			$payload = substr(str_repeat("\x00\xff\x01" . $channel->name, 64), 0, 512);
			self::deliver($offer, $answer, $channel, $payload);
			self::deliver($answer, $offer, $channel, strrev($payload));
			foreach([$offer, $answer] as $peer){
				try{
					$peer->sendFrame($channel, $payload . 'x');
					self::fail('Frame above negotiated capacity accepted');
				}catch(TransportException $e){
					self::assertSame('payload_too_large', $e->errorCode);
				}
			}
		}
		self::assertSame($before, RtcRuntime::getStats()['sendRejectedCount']);
		foreach([$offer, $answer] as $peer){
			self::assertSame('CONNECTED', $peer->getState());
			self::assertNull($peer->getFailureState());
		}
		self::deliver($offer, $answer, Channel::RELIABLE, "after\x00reject");
		self::deliver($answer, $offer, Channel::UNRELIABLE, "after\xffreject");
	}

	/** @return iterable<string, array{Channel}> */
	public static function channels() : iterable{
		yield 'reliable' => [Channel::RELIABLE];
		yield 'unreliable' => [Channel::UNRELIABLE];
	}

	#[DataProvider('channels')]
	public function testRemoteIgnoringAdvertisedLimitIsRejectedAtReceiver(Channel $channel) : void{
		$raw = new PeerConnection(PeerConnectionOptions::create()->setMaxMessageSize(1024));
		$answer = $this->peer(new TransportConfig(maxMessageBytes: 512));
		$outgoing = [];
		try{
			$outgoing[Channel::RELIABLE->name] = $raw->createDataChannel('ReliableDataChannel');
			$outgoing[Channel::UNRELIABLE->name] = $raw->createDataChannel('UnreliableDataChannel', DataChannelOptions::create()->setUnordered(true)->setMaxRetransmits(0));
			self::waitFor(fn() => $raw->getGatheringState() === GatheringState::COMPLETE);
			$answer->setRemoteOffer($raw->getLocalDescription() ?? self::fail('Missing raw offer'));
			self::waitFor(fn() => $answer->isGatheringComplete());
			self::assertSame('512', self::advertisedMessageSize($answer));
			// a misbehaving remote that pretends the receiver admits more
			$inflated = preg_replace('/^a=max-message-size:512(\r?)$/m', 'a=max-message-size:1024$1', $answer->getLocalDescription() ?? '', -1, $replaced);
			self::assertSame(1, $replaced);
			$raw->setRemoteAnswer($inflated ?? self::fail('Cannot inflate answer'));
			self::waitFor(function() use ($answer, $outgoing) : bool{
				$answer->pollChannels();
				return $outgoing[Channel::RELIABLE->name]->isOpen() && $outgoing[Channel::UNRELIABLE->name]->isOpen() &&
					$answer->isChannelOpen(Channel::RELIABLE) && $answer->isChannelOpen(Channel::UNRELIABLE);
			});
			$native = $outgoing[$channel->name];
			self::assertSame(1024, $native->getMaxMessageSize());
			self::assertSame(512, $answer->getMessageCapacity($channel));
			$before = RtcRuntime::getStats()['receiveOverflowCount'];
			self::assertTrue($native->send(str_repeat('z', 1024)));
			self::waitFor(static fn() => RtcRuntime::getStats()['receiveOverflowCount'] > $before);
			self::assertSame($before + 1, RtcRuntime::getStats()['receiveOverflowCount']);
			if($channel === Channel::RELIABLE){
				// reliable loss must fail closed, never expose a truncated prefix
				try{
					$answer->peekFrame($channel);
					self::fail('Reliable overflow was not reported');
				}catch(TransportException $e){
					self::assertSame('native_receive_failed', $e->errorCode);
					self::assertInstanceOf(\amber\rtc\RtcException::class, $e->getPrevious());
					self::assertSame(\amber\rtc\RtcException::RECEIVE_OVERFLOW, $e->getPrevious()->getCode());
				}
			}else{
				self::assertSame(0, $answer->getChannelInfo($channel)['queuedMessages']);
				self::assertTrue($native->send("small\x00"));
				self::waitFor(fn() => $answer->peekFrame($channel) !== null);
				self::assertSame("small\x00", $answer->receiveFrame($channel));
				self::assertTrue($answer->isChannelOpen($channel));
				self::assertSame('CONNECTED', $answer->getState());
			}
		}finally{
			foreach($outgoing as $nativeChannel){ $nativeChannel->close(); }
			$raw->close();
		}
	}

	public function testOversizeFrameRejectedBeforeNativeSend() : void{
		[$offer] = $this->pair(new TransportConfig(maxMessageBytes: 512));
		$before = RtcRuntime::getStats()['sendRejectedCount'];
		try{
			$offer->sendFrame(Channel::RELIABLE, str_repeat('x', 513));
			self::fail('Oversize frame accepted');
		}catch(TransportException $e){
			self::assertSame('payload_too_large', $e->errorCode);
		}
		self::assertSame($before, RtcRuntime::getStats()['sendRejectedCount']);
		self::assertSame('CONNECTED', $offer->getState());
	}

	public function testNativeSendQueueReturnsFalseWithoutLossOrDuplication() : void{
		$config = new TransportConfig(maxMessageBytes: 65536, maxSendQueueBytes: 65536, maxReceiveQueueMessages: 4096, maxReceiveQueueBytes: 16777216);
		[$offer, $answer] = $this->pair($config, $config);
		$before = RtcRuntime::getStats()['sendRejectedCount'];
		$accepted = 0;
		$backpressured = false;
		for($i = 0; $i < 200; ++$i){
			if(!$offer->sendFrame(Channel::RELIABLE, pack('N', $accepted) . str_repeat('x', 65532))){
				$backpressured = true;
				break;
			}
			++$accepted;
		}
		self::assertTrue($backpressured);
		self::assertGreaterThan($before, RtcRuntime::getStats()['sendRejectedCount']);
		self::assertLessThanOrEqual(65536, $offer->getChannelInfo(Channel::RELIABLE)['bufferedBytes']);
		self::waitFor(fn() => $offer->getChannelInfo(Channel::RELIABLE)['bufferedBytes'] === 0);
		self::assertTrue($offer->sendFrame(Channel::RELIABLE, 'barrier'));
		$received = 0;
		self::waitFor(function() use ($answer, &$received) : bool{
			while(($frame = $answer->receiveFrame(Channel::RELIABLE)) !== null){
				if($frame === 'barrier'){ return true; }
				self::assertSame(65536, strlen($frame));
				self::assertSame($received, unpack('N', $frame)[1] ?? null);
				++$received;
			}
			return false;
		});
		self::assertSame($accepted, $received);
	}

	public function testReliableReceiveOverflowIsReportedAsFailure() : void{
		[$offer, $answer] = $this->pair(null, new TransportConfig(maxMessageBytes: 1024, maxReceiveQueueBytes: 1024));
		self::assertTrue($offer->sendFrame(Channel::RELIABLE, str_repeat('x', 700)));
		self::assertTrue($offer->sendFrame(Channel::RELIABLE, str_repeat('y', 700)));
		$error = null;
		self::waitFor(function() use ($answer, &$error) : bool{
			try{ $answer->peekFrame(Channel::RELIABLE); }catch(TransportException $e){ $error = $e; }
			return $error !== null;
		});
		self::assertInstanceOf(TransportException::class, $error);
		self::assertSame('native_receive_failed', $error->errorCode);
		self::assertInstanceOf(\amber\rtc\RtcException::class, $error->getPrevious());
		self::assertSame(\amber\rtc\RtcException::RECEIVE_OVERFLOW, $error->getPrevious()->getCode());
	}

	public function testUnreliableReceiveOverflowDropsWithoutFailure() : void{
		[$offer, $answer] = $this->pair(null, new TransportConfig(maxReceiveQueueMessages: 2));
		$before = RtcRuntime::getStats()['receiveOverflowCount'];
		for($i = 0; $i < 6; ++$i){ self::assertTrue($offer->sendFrame(Channel::UNRELIABLE, "u$i")); }
		self::waitFor(fn() => RtcRuntime::getStats()['receiveOverflowCount'] - $before + $answer->getChannelInfo(Channel::UNRELIABLE)['queuedMessages'] === 6);
		$frames = [];
		while(($frame = $answer->receiveFrame(Channel::UNRELIABLE)) !== null){ $frames[] = $frame; }
		self::assertCount(2, $frames);
		self::assertTrue($answer->isChannelOpen(Channel::UNRELIABLE));
		self::deliver($offer, $answer, Channel::RELIABLE, 'still reliable');
	}

	public function testRemoteDescriptionLimitUsesNativeGuard() : void{
		$peer = $this->peer(new TransportConfig(maxSdpBytes: 32));
		try{
			$peer->setRemoteOffer(str_repeat('x', 33));
			self::fail('Oversize SDP accepted');
		}catch(TransportException $e){
			self::assertSame('negotiation_failed', $e->errorCode);
			self::assertInstanceOf(\amber\rtc\RtcException::class, $e->getPrevious());
			self::assertSame(\amber\rtc\RtcException::SDP_TOO_LARGE, $e->getPrevious()->getCode());
		}
		try{
			$peer->setRemoteAnswer("v=0\r\n");
			self::fail('Answer without local offer accepted');
		}catch(TransportException $e){
			self::assertSame('negotiation_failed', $e->errorCode);
		}
	}

	public function testBoundedUdpCandidatesAndDataExchange() : void{
		$offer = $this->peer(null, 19400, 19410, '127.0.0.1');
		$answer = $this->peer(null, 19411, 19420, '127.0.0.1');
		self::connect($offer, $answer);
		foreach([[$offer, 19400, 19410], [$answer, 19411, 19420]] as [$peer, $begin, $end]){
			preg_match_all('/^a=candidate:\S+ \d+ (\S+) \d+ (\S+) (\d+) typ host/m', $peer->getLocalDescription() ?? '', $matches, PREG_SET_ORDER);
			self::assertNotEmpty($matches);
			foreach($matches as $candidate){
				self::assertSame('UDP', strtoupper($candidate[1]));
				self::assertSame('127.0.0.1', $candidate[2]);
				self::assertGreaterThanOrEqual($begin, (int) $candidate[3]);
				self::assertLessThanOrEqual($end, (int) $candidate[3]);
			}
		}
		self::deliver($offer, $answer, Channel::RELIABLE, "bounded\x00");
		self::deliver($answer, $offer, Channel::UNRELIABLE, "bounded\xff");
	}

	public static function freeUdpPort(string $host = '127.0.0.1') : int{
		// below the os ephemeral ranges, so later sockets cannot be handed the same port
		for($attempt = 0; $attempt < 1000; ++$attempt){
			$port = random_int(20000, 32000);
			$probe = @stream_socket_server('udp://' . $host . ':' . $port, $code, $error, STREAM_SERVER_BIND);
			if(is_resource($probe)){
				fclose($probe);
				return $port;
			}
		}
		self::fail('No free UDP port');
	}

	/** @return list<string> */
	public static function hostCandidates(string $sdp) : array{
		preg_match_all('/^a=candidate:\S+ \d+ \S+ \d+ (\S+) (\d+) typ host/m', $sdp, $matches, PREG_SET_ORDER);
		return array_map(static fn(array $m) : string => $m[1] . ':' . $m[2], $matches);
	}

	private static function assertNoPendingFrames(ExtRtcPeer ...$peers) : void{
		foreach($peers as $peer){
			foreach([Channel::RELIABLE, Channel::UNRELIABLE] as $channel){ self::assertNull($peer->peekFrame($channel)); }
		}
	}

	public function testUdpMuxSharesOnePortAcrossIsolatedPeers() : void{
		$port = self::freeUdpPort();
		$offers = [];
		$answers = [];
		for($i = 0; $i < 3; ++$i){
			$offers[$i] = $this->peer(null, 0, 0, '127.0.0.1');
			$answers[$i] = $this->peer(null, $port, $port, '127.0.0.1', true);
			self::connect($offers[$i], $answers[$i]);
			self::assertSame(['127.0.0.1:' . $port], self::hostCandidates($answers[$i]->getLocalDescription() ?? ''));
		}
		self::assertCount(3, array_unique(array_map(static fn(ExtRtcPeer $peer) : string => $peer->getRemoteFingerprint() ?? '', $answers)));
		foreach($answers as $i => $answer){
			foreach([Channel::RELIABLE, Channel::UNRELIABLE] as $channel){
				self::deliver($offers[$i], $answer, $channel, "to\x00$i" . $channel->name);
				self::deliver($answer, $offers[$i], $channel, "from\xff$i" . $channel->name);
			}
		}
		// late cross-peer delivery would show up here
		usleep(100000);
		self::assertNoPendingFrames(...$offers, ...$answers);
		$answers[0]->close();
		$offers[0]->close();
		foreach([1, 2] as $i){
			self::assertSame('CONNECTED', $answers[$i]->getState());
			self::deliver($offers[$i], $answers[$i], Channel::RELIABLE, "after\x00leave$i");
			self::deliver($answers[$i], $offers[$i], Channel::UNRELIABLE, "after\xffleave$i");
		}
		foreach([...$offers, ...$answers] as $peer){ $peer->close(); }
		$this->peers = [];
		self::waitFor(static fn() => RtcRuntime::getStats()['activePeers'] === 0);
		// quick reconnects reuse the port while the previous shared socket may still be closing
		for($round = 0; $round < 5; ++$round){
			$offer = $this->peer(null, 0, 0, '127.0.0.1');
			$answer = $this->peer(null, $port, $port, '127.0.0.1', true);
			self::connect($offer, $answer);
			self::assertSame(['127.0.0.1:' . $port], self::hostCandidates($answer->getLocalDescription() ?? ''));
			self::deliver($offer, $answer, Channel::RELIABLE, "round\x00$round");
			$offer->close();
			$answer->close();
		}
	}

	public function testUdpMuxConflictsFailConstructionExplicitly() : void{
		$port = self::freeUdpPort();
		$busy = stream_socket_server('udp://127.0.0.1:' . $port, $code, $error, STREAM_SERVER_BIND);
		self::assertIsResource($busy);
		try{
			$this->assertNativeRejection($port, '127.0.0.1', 'ICE UDP mux port is unavailable');
		}finally{
			fclose($busy);
		}
		$first = $this->peer(null, $port, $port, '127.0.0.1', true);
		$this->assertNativeRejection($port, '127.0.0.2', 'ICE UDP mux port is shared with a different bind address');
		self::assertSame(1, RtcRuntime::getStats()['activePeers']);
		$first->close();
	}

	private function assertNativeRejection(int $port, string $bind, string $message) : void{
		try{
			$this->peer(null, $port, $port, $bind, true);
			self::fail('Conflicting mux peer accepted');
		}catch(TransportException $e){
			self::assertSame('backend_error', $e->errorCode);
			self::assertSame($message, $e->getMessage());
			self::assertInstanceOf(\amber\rtc\RtcException::class, $e->getPrevious());
			self::assertSame(\amber\rtc\RtcException::INVALID_ARGUMENT, $e->getPrevious()->getCode());
		}
	}

	public function testUdpMuxOverIpv6Loopback() : void{
		$probe = @stream_socket_server('udp://[::1]:0', $code, $error, STREAM_SERVER_BIND);
		if(!is_resource($probe)){ self::markTestSkipped('IPv6 loopback is unavailable'); }
		fclose($probe);
		$port = self::freeUdpPort('[::1]');
		$offers = [];
		$answers = [];
		for($i = 0; $i < 2; ++$i){
			$offers[$i] = $this->peer(null, 0, 0, '::1');
			$answers[$i] = $this->peer(null, $port, $port, '::1', true);
			self::connect($offers[$i], $answers[$i]);
			self::assertSame(['::1:' . $port], self::hostCandidates($answers[$i]->getLocalDescription() ?? ''));
		}
		foreach($answers as $i => $answer){
			self::deliver($offers[$i], $answer, Channel::RELIABLE, "v6\x00$i");
			self::deliver($answer, $offers[$i], Channel::UNRELIABLE, "v6\xff$i");
		}
		self::assertNoPendingFrames(...$offers, ...$answers);
	}

	public function testTcpMdnsAndRtcpCandidatesInRemoteOfferAreSkipped() : void{
		$offer = $this->peer(null, 0, 0, '127.0.0.1');
		$offer->createChannel(Channel::RELIABLE);
		$offer->createChannel(Channel::UNRELIABLE);
		self::waitFor(fn() => $offer->isGatheringComplete());
		// what libwebrtc clients add next to their udp host candidates
		$extra = "a=candidate:2 1 tcp 1518280447 127.0.0.1 9 typ host tcptype active generation 0 network-id 1\r\n" .
			"a=candidate:3 1 udp 2122194687 4b0bd1ec-0c4b-4f3e-9d8f-3c0e2f1a7b6d.local 50000 typ host generation 0\r\n" .
			"a=candidate:4 1 TCP 1518280447 127.0.0.1 50001 typ host tcptype passive\r\n" .
			"a=candidate:5 2 udp 2130706431 127.0.0.1 50002 typ host ufrag x\r\n";
		$sdp = preg_replace('/^(a=candidate:[^\r\n]*\r?\n)/m', '$1' . $extra, $offer->getLocalDescription() ?? '', 1);
		self::assertIsString($sdp);
		self::assertStringContainsString('tcptype active', $sdp);
		// the native validator alone rejects the whole description
		$raw = new PeerConnection(PeerConnectionOptions::create());
		try{
			$raw->setRemoteOffer($sdp);
			self::fail('Native accepted a tcp candidate');
		}catch(\amber\rtc\RtcException $e){
			self::assertSame(\amber\rtc\RtcException::INVALID_SDP, $e->getCode());
		}finally{
			$raw->close();
		}
		$answer = $this->peer(null, 0, 0, '127.0.0.1');
		$answer->setRemoteOffer($sdp);
		self::waitFor(fn() => $answer->isGatheringComplete());
		$offer->setRemoteAnswer($answer->getLocalDescription() ?? self::fail('Missing answer'));
		self::waitFor(function() use ($offer, $answer) : bool{
			$answer->pollChannels();
			return $offer->isChannelOpen(Channel::RELIABLE) && $answer->isChannelOpen(Channel::RELIABLE) && $answer->isChannelOpen(Channel::UNRELIABLE);
		});
		self::deliver($offer, $answer, Channel::RELIABLE, "tcp\x00skipped");
		self::deliver($answer, $offer, Channel::UNRELIABLE, "mdns\xffskipped");
	}

	/** @return iterable<string, array{string}> */
	public static function malformedCandidates() : iterable{
		yield 'truncated' => ["a=candidate:2 1 udp 1 127.0.0.1\r\n"];
		yield 'bad port' => ["a=candidate:2 1 udp 1 127.0.0.1 70000 typ host\r\n"];
		yield 'unknown component' => ["a=candidate:2 3 udp 1 127.0.0.1 50000 typ host\r\n"];
		yield 'zero port' => ["a=candidate:2 1 udp 1 127.0.0.1 0 typ host\r\n"];
		yield 'bad type' => ["a=candidate:2 1 udp 1 127.0.0.1 50000 typ bogus\r\n"];
	}

	#[DataProvider('malformedCandidates')]
	public function testMalformedCandidatesStillFailNegotiation(string $line) : void{
		$offer = $this->peer();
		$offer->createChannel(Channel::RELIABLE);
		self::waitFor(fn() => $offer->isGatheringComplete());
		$sdp = preg_replace('/^(a=candidate:[^\r\n]*\r?\n)/m', '$1' . $line, $offer->getLocalDescription() ?? '', 1);
		self::assertIsString($sdp);
		try{
			$this->peer()->setRemoteOffer($sdp);
			self::fail('Malformed candidate accepted');
		}catch(TransportException $e){
			self::assertSame('negotiation_failed', $e->errorCode);
			self::assertInstanceOf(\amber\rtc\RtcException::class, $e->getPrevious());
			self::assertSame(\amber\rtc\RtcException::INVALID_SDP, $e->getPrevious()->getCode());
		}
	}

	public function testWindowsMuxRequiresExplicitBindBeforeNativeConstruction() : void{
		if(PHP_OS_FAMILY !== 'Windows'){
			// wildcard mux stays supported elsewhere
			$this->peer(null, $port = self::freeUdpPort(), $port, null, true)->close();
			self::assertSame(0, RtcRuntime::getStats()['activePeers']);
			return;
		}
		foreach([null, '0.0.0.0', '::'] as $bind){
			try{
				$this->peer(null, 19133, 19133, $bind, true);
				self::fail('Windows wildcard mux accepted');
			}catch(\InvalidArgumentException $e){
				self::assertStringContainsString('non-wildcard', $e->getMessage());
			}
		}
		self::assertSame(0, RtcRuntime::getStats()['activePeers']);
	}

	/** @return iterable<string, array{int, int, ?string}> */
	public static function nativeRejectedOptions() : iterable{
		yield 'unavailable IPv4' => [0, 0, '192.0.2.1'];
		yield 'unavailable IPv6' => [0, 0, '2001:db8::1'];
		yield 'unenforceable range' => [1, 65535, null];
	}

	#[DataProvider('nativeRejectedOptions')]
	public function testNativeOptionRejectionFailsConstruction(int $begin, int $end, ?string $bind) : void{
		try{
			$this->peer(null, $begin, $end, $bind);
			self::fail('Native accepted an unenforceable configuration');
		}catch(TransportException $e){
			self::assertSame('backend_error', $e->errorCode);
			self::assertInstanceOf(\amber\rtc\RtcException::class, $e->getPrevious());
			self::assertSame(\amber\rtc\RtcException::INVALID_ARGUMENT, $e->getPrevious()->getCode());
		}
		self::assertSame(0, RtcRuntime::getStats()['activePeers']);
	}

	public function testUseAfterCloseAndRepeatedLifecycleDoNotLeak() : void{
		for($i = 0; $i < 20; ++$i){
			[$offer, $answer] = $this->pair();
			self::deliver($offer, $answer, Channel::RELIABLE, "round\x00$i");
			$offer->close();
			$offer->close();
			$answer->close();
			self::assertSame('CLOSED', $offer->getState());
			self::assertFalse($offer->isChannelOpen(Channel::RELIABLE));
			foreach([
				fn() => $offer->sendFrame(Channel::RELIABLE, 'late'),
				fn() => $offer->peekFrame(Channel::RELIABLE),
				fn() => $offer->getLocalDescription(),
				fn() => $offer->createChannel(Channel::RELIABLE)
			] as $operation){
				try{ $operation(); self::fail('Use after close succeeded'); }
				catch(TransportException $e){ self::assertSame('closed', $e->errorCode); }
			}
			$this->peers = [];
			self::waitFor(static fn() => RtcRuntime::getStats()['activePeers'] === 0 && RtcRuntime::getStats()['activeChannels'] === 0);
		}
	}

	public function testDuplicateLocalChannelAndCloneAreRejected() : void{
		$peer = $this->peer();
		$peer->createChannel(Channel::RELIABLE);
		try{ $peer->createChannel(Channel::RELIABLE); self::fail('Duplicate local channel'); }
		catch(TransportException $e){ self::assertSame('channel_invalid', $e->errorCode); }
		$this->expectException(\Error::class);
		$this->peers[] = clone $peer;
	}

	public function testPendingChannelLimitBoundsUncollectedHandoff() : void{
		$raw = new PeerConnection(PeerConnectionOptions::create());
		$answer = $this->peer();
		$outgoing = [];
		try{
			$outgoing[] = $raw->createDataChannel('ReliableDataChannel');
			$outgoing[] = $raw->createDataChannel('UnreliableDataChannel', DataChannelOptions::create()->setUnordered(true)->setMaxRetransmits(0));
			self::exchange($raw, $answer);
			self::waitFor(fn() => $outgoing[0]->isOpen() && $outgoing[1]->isOpen());
			$outgoing[] = $raw->createDataChannel('extra');
			usleep(250000);
			self::assertEqualsCanonicalizing([Channel::RELIABLE, Channel::UNRELIABLE], $answer->pollChannels());
			self::assertSame([], $answer->pollChannels());
		}finally{
			foreach($outgoing as $channel){ $channel->close(); }
			$raw->close();
		}
	}

	private static function exchange(PeerConnection $raw, ExtRtcPeer $answer) : void{
		self::waitFor(fn() => $raw->getGatheringState() === GatheringState::COMPLETE);
		$answer->setRemoteOffer($raw->getLocalDescription() ?? self::fail('Missing raw offer'));
		self::waitFor(fn() => $answer->isGatheringComplete());
		$raw->setRemoteAnswer($answer->getLocalDescription() ?? self::fail('Missing answer'));
	}

	/** @return iterable<string, array{string, bool, ?int, ?int, string, bool}> */
	public static function invalidChannelProperties() : iterable{
		yield 'unknown label' => ['unknown', false, null, null, '', false];
		yield 'wrong protocol' => ['ReliableDataChannel', false, null, null, 'unexpected', false];
		yield 'unordered reliable' => ['ReliableDataChannel', true, null, null, '', false];
		yield 'lossy reliable' => ['ReliableDataChannel', false, 0, null, '', false];
		yield 'lifetime on reliable' => ['ReliableDataChannel', false, null, 10, '', false];
		yield 'reliable unreliable' => ['UnreliableDataChannel', true, null, null, '', false];
		yield 'ordered unreliable' => ['UnreliableDataChannel', false, 0, null, '', false];
		yield 'duplicate channel' => ['ReliableDataChannel', false, null, null, '', true];
	}

	#[DataProvider('invalidChannelProperties')]
	public function testRemoteChannelPropertiesAreValidated(string $label, bool $unordered, ?int $retransmits, ?int $lifetime, string $protocol, bool $duplicate) : void{
		$raw = new PeerConnection(PeerConnectionOptions::create()->setMaxPendingDataChannels(4));
		$answer = $this->peer();
		$outgoing = [];
		try{
			$options = DataChannelOptions::create()->setUnordered($unordered)->setProtocol($protocol);
			if($lifetime !== null){ $options->setMaxPacketLifeTime($lifetime); }else{ $options->setMaxRetransmits($retransmits); }
			// dropping an ext-rtc channel handle closes the channel
			$outgoing = [$raw->createDataChannel($label, $options)];
			if($duplicate){ $outgoing[] = $raw->createDataChannel($label, $options); }
			self::exchange($raw, $answer);
			$error = null;
			self::waitFor(function() use ($answer, &$error) : bool{
				try{ $answer->pollChannels(); }catch(TransportException $e){ $error = $e; }
				return $error !== null;
			});
			self::assertInstanceOf(TransportException::class, $error);
			self::assertSame('channel_invalid', $error->errorCode);
			self::assertSame('CLOSED', $answer->getState());
			self::assertFalse($answer->isChannelOpen(Channel::RELIABLE));
		}finally{
			foreach($outgoing as $channel){ $channel->close(); }
			$raw->close();
		}
	}
}
