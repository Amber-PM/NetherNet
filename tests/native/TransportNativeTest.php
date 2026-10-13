<?php

declare(strict_types=1);

namespace amber\nethernet\tests\native;

use amber\nethernet\backend\ExtWebRtcPeer;
use amber\nethernet\Channel;
use amber\nethernet\ConnectionState;
use amber\nethernet\framing\FrameCodec;
use amber\nethernet\identity\ClientServerIdentityHandler;
use amber\nethernet\identity\SdpIdentity;
use amber\nethernet\tests\identity\IdentityFixture;
use amber\nethernet\tests\transport\RecordingListener;
use amber\nethernet\Transport;
use amber\nethernet\TransportConfig;
use PHPUnit\Framework\TestCase;

final class TransportNativeTest extends TestCase{
	/** @param \Closure(): bool $condition */
	private static function waitFor(\Closure $condition) : void{
		$deadline = hrtime(true) + 10_000_000_000;
		while(!$condition()){
			if(hrtime(true) >= $deadline){ self::fail('Native transport did not complete in ten seconds'); }
			usleep(1000);
		}
	}

	public function testAuthenticatedTransportExchangesFragmentedAndUnreliableMessagesAndCloses() : void{
		$fixture = new IdentityFixture();
		$config = new TransportConfig(maxMessageBytes: 512);
		$listener = new RecordingListener();
		$transport = new Transport($config, new ClientServerIdentityHandler($fixture->verifier(), $fixture->server), $listener);
		$client = new ExtWebRtcPeer($config);
		try{
			$client->createChannel(Channel::RELIABLE);
			$client->createChannel(Channel::UNRELIABLE);
			self::waitFor(fn() => $client->isGatheringComplete());
			$sdp = $client->getLocalDescription();
			self::assertNotNull($sdp);
			$id = $transport->accept('native-network', $fixture->offer($sdp, time()));
			$listener->answered = function(int $answerId) use ($listener, $client, $config) : void{
				$answer = SdpIdentity::fromSdp($listener->answers[$answerId], $config);
				self::assertSame('operator.test', $answer->providerDomain);
				$client->setRemoteAnswer($answer->sdpWithoutIdentity);
			};
			self::waitFor(function() use ($transport, $listener, $id) : bool{
				$transport->poll();
				return isset($listener->connections[$id]);
			});
			$connection = $listener->connections[$id];
			self::assertSame('player', $connection->getIdentity()->subject);
			self::assertSame(['answer', 'open'], $listener->events);
			$payload = str_repeat("\x00\xffabc", 400);
			$codec = new FrameCodec($config);
			foreach($codec->encode($payload, 512) as $frame){ self::assertTrue($client->sendFrame(Channel::RELIABLE, $frame)); }
			self::assertTrue($client->sendFrame(Channel::UNRELIABLE, "\0\xffunreliable"));
			self::waitFor(function() use ($transport, $listener) : bool{ $transport->poll(); return count($listener->payloads) === 2; });
			self::assertContains([$id, $payload, Channel::RELIABLE], $listener->payloads);
			self::assertContains([$id, "\xffunreliable", Channel::UNRELIABLE], $listener->payloads);
			$accepted = new \stdClass();
			$accepted->values = [];
			$connection->send($payload, accepted: function(bool $ok) use ($accepted) : void{ $accepted->values[] = $ok; });
			$received = null;
			self::waitFor(function() use ($transport, $client, $codec, &$received) : bool{
				$transport->poll();
				while(($frame = $client->receiveFrame(Channel::RELIABLE)) !== null){
					$received = $codec->receive($frame, Channel::RELIABLE, 512, hrtime(true) / 1_000_000_000);
				}
				return $received !== null;
			});
			self::assertSame($payload, $received);
			self::assertSame([true], $accepted->values);
			$transport->stop();
			self::assertSame(ConnectionState::CLOSED, $connection->getState());
			self::assertSame(['answer', 'open', 'close'], $listener->events);
			$transport->stop();
		}finally{
			$transport->stop();
			$client->close();
		}
	}

	public function testNativeUnexpectedChannelFailsBeforeOpen() : void{
		$fixture = new IdentityFixture();
		$config = new TransportConfig();
		$listener = new RecordingListener();
		$transport = new Transport($config, new ClientServerIdentityHandler($fixture->verifier(), $fixture->server), $listener);
		$client = new \pmmp\webrtc\PeerConnection(\pmmp\webrtc\PeerConnectionOptions::create());
		$channels = [];
		try{
			$channels[] = $client->createDataChannel('ReliableDataChannel');
			$channels[] = $client->createDataChannel('unexpected');
			self::waitFor(fn() => $client->getGatheringState() === \pmmp\webrtc\GatheringState::COMPLETE);
			$sdp = $client->getLocalDescription();
			self::assertNotNull($sdp);
			$transport->accept('bad-channel', $fixture->offer($sdp, time()));
			$listener->answered = function(int $id) use ($client, $listener, $config) : void{
				$client->setRemoteAnswer(SdpIdentity::fromSdp($listener->answers[$id], $config)->sdpWithoutIdentity);
			};
			self::waitFor(function() use ($transport, $listener) : bool{ $transport->poll(); return $listener->closed !== []; });
			self::assertSame('channel_invalid', $listener->closed[0][1]);
			self::assertSame([], $listener->connections);
			self::assertSame(['answer', 'close'], $listener->events);
		}finally{
			$transport->stop();
			foreach($channels as $channel){ $channel->close(); }
			$client->close();
		}
	}

	public function testConcurrentNativeConnectionsAndRepeatedTransportShutdown() : void{
		$fixture = new IdentityFixture();
		$config = new TransportConfig();
		for($cycle = 0; $cycle < 4; ++$cycle){
			$listener = new RecordingListener();
			$transport = new Transport($config, new ClientServerIdentityHandler($fixture->verifier(), $fixture->server), $listener);
			$clients = [];
			try{
				for($index = 0; $index < 2; ++$index){
					$client = new ExtWebRtcPeer($config);
					$clients[$index + 1] = $client;
					$client->createChannel(Channel::RELIABLE);
					$client->createChannel(Channel::UNRELIABLE);
					self::waitFor(fn() => $client->isGatheringComplete());
					$sdp = $client->getLocalDescription();
					self::assertNotNull($sdp);
					$transport->accept('client-' . $index, $fixture->offer($sdp, time()));
				}
				$listener->answered = static function(int $id) use ($clients, $listener, $config) : void{
					$clients[$id]->setRemoteAnswer(SdpIdentity::fromSdp($listener->answers[$id], $config)->sdpWithoutIdentity);
				};
				self::waitFor(function() use ($transport, $listener) : bool{ $transport->poll(); return count($listener->connections) === 2; });
				$transport->stop();
				self::assertCount(2, $listener->closed);
				foreach($listener->connections as $connection){ self::assertSame(ConnectionState::CLOSED, $connection->getState()); }
			}finally{
				$transport->stop();
				foreach($clients as $client){ $client->close(); }
			}
		}
	}
}
