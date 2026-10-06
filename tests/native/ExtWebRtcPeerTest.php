<?php

declare(strict_types=1);

namespace amber\nethernet\tests\native;

use amber\nethernet\Channel;
use amber\nethernet\TransportConfig;
use amber\nethernet\TransportException;
use amber\nethernet\backend\ExtWebRtcPeer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ExtWebRtcPeerTest extends TestCase{
	/** @var list<ExtWebRtcPeer> */
	private array $peers = [];

	protected function tearDown() : void{
		foreach($this->peers as $peer){
			$peer->close();
		}
		$this->peers = [];
	}

	/** @param \Closure(): bool $condition */
	private static function waitFor(\Closure $condition) : void{
		$deadline = hrtime(true) + 10_000_000_000;
		while(!$condition()){
			if(hrtime(true) >= $deadline){
				self::fail('Native operation did not complete within ten seconds');
			}
			usleep(1000);
		}
	}

	/** @return array{ExtWebRtcPeer, ExtWebRtcPeer} */
	private function pair(?TransportConfig $offerConfig = null, ?TransportConfig $answerConfig = null) : array{
		$offer = new ExtWebRtcPeer($offerConfig ?? new TransportConfig());
		$this->peers[] = $offer;
		$answer = new ExtWebRtcPeer($answerConfig ?? new TransportConfig());
		$this->peers[] = $answer;
		$offer->createChannel(Channel::RELIABLE);
		$offer->createChannel(Channel::UNRELIABLE);
		self::waitFor(fn() => $offer->isGatheringComplete());
		$sdp = $offer->getLocalDescription();
		self::assertNotNull($sdp);
		$answer->setRemoteOffer($sdp);
		self::waitFor(fn() => $answer->isGatheringComplete());
		$sdp = $answer->getLocalDescription();
		self::assertNotNull($sdp);
		$offer->setRemoteAnswer($sdp);
		self::waitFor(function() use ($answer, $offer) : bool{
			$answer->pollChannels();
			return $offer->isChannelOpen(Channel::RELIABLE) && $offer->isChannelOpen(Channel::UNRELIABLE) &&
				$answer->isChannelOpen(Channel::RELIABLE) && $answer->isChannelOpen(Channel::UNRELIABLE);
		});
		return [$offer, $answer];
	}

	public function testBinaryMessagesBothChannelsAndNegotiatedCapacity() : void{
		ExtWebRtcPeer::assertAvailable();
		[$offer, $answer] = $this->pair(new TransportConfig(maxMessageBytes: 1024), new TransportConfig(maxMessageBytes: 512));
		self::assertSame('CONNECTED', $offer->getState());
		self::assertSame('CONNECTED', $answer->getState());
		self::assertNull($answer->getFailureState());
		self::assertMatchesRegularExpression('/^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/', $answer->getRemoteFingerprint() ?? '');
		self::assertSame([], $answer->pollChannels());
		foreach([Channel::RELIABLE, Channel::UNRELIABLE] as $channel){
			$info = $answer->getChannelInfo($channel);
			self::assertSame($channel === Channel::RELIABLE ? 'ReliableDataChannel' : 'UnreliableDataChannel', $info['label']);
			self::assertSame('', $info['protocol']);
			self::assertSame($channel === Channel::UNRELIABLE, $info['unordered']);
			self::assertSame($channel === Channel::UNRELIABLE ? 0 : null, $info['maxRetransmits']);
			self::assertNull($info['maxPacketLifeTime']);
			self::assertSame(512, $offer->getMessageCapacity($channel));
			self::assertSame(512, $answer->getMessageCapacity($channel));
			$payload = "\x00\x01\xfe\xffhello\x00";
			self::assertTrue($offer->sendFrame($channel, $payload));
			self::waitFor(fn() => $answer->peekFrame($channel) !== null);
			self::assertSame($payload, $answer->peekFrame($channel));
			self::assertSame($payload, $answer->receiveFrame($channel));
			self::assertNull($answer->receiveFrame($channel));
			self::assertTrue($answer->sendFrame($channel, str_repeat("\x00\xff", 256)));
			self::waitFor(fn() => $offer->peekFrame($channel) !== null);
			self::assertSame(str_repeat("\x00\xff", 256), $offer->receiveFrame($channel));
		}
	}

	public function testRepeatedPeerLifecycleAndUseAfterClose() : void{
		for($i = 0; $i < 3; ++$i){
			[$offer, $answer] = $this->pair();
			self::assertTrue($offer->sendFrame(Channel::RELIABLE, "round\x00$i"));
			self::waitFor(fn() => $answer->peekFrame(Channel::RELIABLE) !== null);
			self::assertSame("round\x00$i", $answer->receiveFrame(Channel::RELIABLE));
			$offer->close();
			$answer->close();
			$offer->close();
			self::assertSame('CLOSED', $offer->getState());
		}
		$this->expectException(TransportException::class);
		$offer->sendFrame(Channel::RELIABLE, 'after close');
	}

	public function testOversizeFrameRejectedBeforeNativeSend() : void{
		[$offer] = $this->pair(new TransportConfig(maxMessageBytes: 512));
		$this->expectException(TransportException::class);
		$offer->sendFrame(Channel::RELIABLE, str_repeat('x', 513));
	}

	public function testCloningCannotCreateTwoOwnersOfTheSameNativePeer() : void{
		$peer = new ExtWebRtcPeer(new TransportConfig());
		$this->peers[] = $peer;
		$this->expectException(\Error::class);
		$this->peers[] = clone $peer;
	}

	public function testRemoteDescriptionLimitUsesNativeGuard() : void{
		$peer = new ExtWebRtcPeer(new TransportConfig(maxSdpBytes: 32));
		$this->peers[] = $peer;
		try{
			$peer->setRemoteOffer(str_repeat('x', 33));
			self::fail('Oversize SDP accepted');
		}catch(TransportException $e){
			self::assertSame('backend_error', $e->errorCode);
			self::assertInstanceOf(\RuntimeException::class, $e->getPrevious());
			self::assertStringContainsString('over the 32 byte limit', $e->getMessage());
		}
	}

	public function testReceiveByteBudgetReportsLossInsteadOfPartialStream() : void{
		[$offer, $answer] = $this->pair(null, new TransportConfig(maxMessageBytes: 1024, maxReceiveQueueBytes: 1024));
		self::assertTrue($offer->sendFrame(Channel::RELIABLE, str_repeat('x', 700)));
		self::assertTrue($offer->sendFrame(Channel::RELIABLE, str_repeat('y', 700)));
		self::waitFor(fn() => $answer->getChannelInfo(Channel::RELIABLE)['closed']);
		self::assertSame(700, $answer->getChannelInfo(Channel::RELIABLE)['availableBytes']);
		try{
			$answer->receiveFrame(Channel::RELIABLE);
			self::fail('Receive overflow did not report loss');
		}catch(TransportException $e){
			self::assertSame('native_receive_failed', $e->errorCode);
		}
	}

	public function testReceiveMessageBudgetCountsEmptyMessages() : void{
		[$offer, $answer] = $this->pair(null, new TransportConfig(maxReceiveQueueMessages: 1));
		self::assertTrue($offer->sendFrame(Channel::RELIABLE, ''));
		self::assertTrue($offer->sendFrame(Channel::RELIABLE, ''));
		self::waitFor(fn() => $answer->getChannelInfo(Channel::RELIABLE)['closed']);
		self::assertSame(1, $answer->getChannelInfo(Channel::RELIABLE)['queuedMessages']);
		$this->expectException(TransportException::class);
		$answer->peekFrame(Channel::RELIABLE);
	}

	public function testNativeSendBudgetReturnsBackpressureWithoutOvershoot() : void{
		$config = new TransportConfig(maxMessageBytes: 262144, maxSendQueueBytes: 262144, maxReceiveQueueMessages: 4096, maxReceiveQueueBytes: 67108864);
		[$offer, $answer] = $this->pair($config, $config);
		$backpressured = false;
		$acceptedCount = 0;
		for($i = 0; $i < 4096; ++$i){
			if(!$offer->sendFrame(Channel::RELIABLE, str_repeat('x', 262144))){
				$backpressured = true;
				break;
			}
			++$acceptedCount;
		}
		self::assertTrue($backpressured);
		if($offer->sendFrame(Channel::RELIABLE, '')){
			++$acceptedCount;
		}
		self::assertLessThanOrEqual(262144, $offer->getChannelInfo(Channel::RELIABLE)['bufferedBytes']);
		self::waitFor(fn() => $offer->getChannelInfo(Channel::RELIABLE)['bufferedBytes'] === 0);
		self::assertTrue($offer->sendFrame(Channel::RELIABLE, 'barrier'));
		$receivedCount = 0;
		self::waitFor(function() use ($answer, &$receivedCount) : bool{
			$frame = $answer->receiveFrame(Channel::RELIABLE);
			if($frame === 'barrier'){
				return true;
			}
			if($frame !== null){
				++$receivedCount;
			}
			return false;
		});
		self::assertSame($acceptedCount, $receivedCount);
	}

	/** @return iterable<string, array{string, bool, ?int, ?int, string, bool}> */
	public static function invalidChannelProperties() : iterable{
		yield 'unknown label' => ['unknown', false, null, null, '', false];
		yield 'wrong protocol' => ['ReliableDataChannel', false, null, null, 'unexpected', false];
		yield 'unordered reliable' => ['ReliableDataChannel', true, null, null, '', false];
		yield 'lossy reliable' => ['ReliableDataChannel', false, 0, null, '', false];
		yield 'lifetime on reliable' => ['ReliableDataChannel', false, null, 10, '', false];
		yield 'reliable unreliable' => ['UnreliableDataChannel', true, null, null, '', false];
		yield 'duplicate channel' => ['ReliableDataChannel', false, null, null, '', true];
	}

	public function testNativePendingChannelLimitBoundsUncollectedHandoff() : void{
		$raw = new \pmmp\webrtc\PeerConnection(\pmmp\webrtc\PeerConnectionOptions::create()->setMaxMessageSize(262144));
		$answer = new ExtWebRtcPeer(new TransportConfig());
		$this->peers[] = $answer;
		$outgoing = [];
		try{
			$outgoing[] = $raw->createDataChannel('ReliableDataChannel');
			$outgoing[] = $raw->createDataChannel('UnreliableDataChannel', \pmmp\webrtc\DataChannelOptions::create()->setUnordered(true)->setMaxRetransmits(0));
			self::waitFor(fn() => $raw->getGatheringState() === \pmmp\webrtc\GatheringState::COMPLETE);
			$sdp = $raw->getLocalDescription();
			self::assertNotNull($sdp);
			$answer->setRemoteOffer($sdp);
			self::waitFor(fn() => $answer->isGatheringComplete());
			$sdp = $answer->getLocalDescription();
			self::assertNotNull($sdp);
			$raw->setRemoteAnswer($sdp);
			self::waitFor(fn() => $outgoing[0]->isOpen() && $outgoing[1]->isOpen());
			$outgoing[] = $raw->createDataChannel('extra');
			usleep(250000);
			self::assertEqualsCanonicalizing([Channel::RELIABLE, Channel::UNRELIABLE], $answer->pollChannels());
			self::assertSame([], $answer->pollChannels());
		}finally{
			foreach($outgoing as $channel){
				$channel->close();
			}
			$raw->close();
		}
	}

	#[DataProvider('invalidChannelProperties')]
	public function testRemoteChannelPropertiesAreValidated(string $label, bool $unordered, ?int $retransmits, ?int $lifetime, string $protocol, bool $duplicate) : void{
		$raw = new \pmmp\webrtc\PeerConnection(\pmmp\webrtc\PeerConnectionOptions::create()->setMaxMessageSize(262144));
		$answer = new ExtWebRtcPeer(new TransportConfig());
		$this->peers[] = $answer;
		try{
			$options = \pmmp\webrtc\DataChannelOptions::create()->setUnordered($unordered)
				->setMaxRetransmits($retransmits)->setMaxPacketLifeTime($lifetime)->setProtocol($protocol);
			$outgoing = [$raw->createDataChannel($label, $options)];
			if($duplicate){
				$outgoing[] = $raw->createDataChannel($label, $options);
			}
			self::waitFor(fn() => $raw->getGatheringState() === \pmmp\webrtc\GatheringState::COMPLETE);
			$sdp = $raw->getLocalDescription();
			self::assertNotNull($sdp);
			$answer->setRemoteOffer($sdp);
			self::waitFor(fn() => $answer->isGatheringComplete());
			$sdp = $answer->getLocalDescription();
			self::assertNotNull($sdp);
			$raw->setRemoteAnswer($sdp);
			try{
				self::waitFor(function() use ($answer) : bool{
					$answer->pollChannels();
					return false;
				});
			}catch(TransportException $e){
				self::assertSame('channel_invalid', $e->errorCode);
				self::assertSame('CLOSED', $answer->getState());
			}
		}finally{
			foreach($outgoing ?? [] as $channel){
				$channel->close();
			}
			$raw->close();
		}
	}
}
