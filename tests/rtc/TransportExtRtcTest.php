<?php

declare(strict_types=1);

namespace amber\nethernet\tests\rtc;

use amber\nethernet\backend\ExtRtcPeer;
use amber\nethernet\backend\WebRtcPeer;
use amber\nethernet\Channel;
use amber\nethernet\ConnectionState;
use amber\nethernet\framing\FrameCodec;
use amber\nethernet\identity\ClientServerIdentityHandler;
use amber\nethernet\identity\SdpIdentity;
use amber\nethernet\SendResult;
use amber\nethernet\tests\identity\IdentityFixture;
use amber\nethernet\tests\transport\RecordingListener;
use amber\nethernet\Transport;
use amber\nethernet\TransportConfig;
use amber\rtc\GatheringState;
use amber\rtc\PeerConnection;
use amber\rtc\PeerConnectionOptions;
use amber\rtc\RtcRuntime;
use PHPUnit\Framework\TestCase;

final class TransportExtRtcTest extends TestCase{
	protected function tearDown() : void{
		ExtRtcPeerTest::waitFor(static fn() => RtcRuntime::getStats()['activePeers'] === 0 && RtcRuntime::getStats()['activeChannels'] === 0);
	}

	private static function transport(TransportConfig $config, IdentityFixture $fixture, RecordingListener $listener) : Transport{
		return new Transport($config, new ClientServerIdentityHandler($fixture->verifier(), $fixture->server), $listener, static fn() : WebRtcPeer => new ExtRtcPeer($config));
	}

	private static function offer(ExtRtcPeer $client) : string{
		$client->createChannel(Channel::RELIABLE);
		$client->createChannel(Channel::UNRELIABLE);
		ExtRtcPeerTest::waitFor(fn() => $client->isGatheringComplete());
		return $client->getLocalDescription() ?? self::fail('Missing client offer');
	}

	public function testAuthenticatedTransportExchangesFragmentedAndUnreliableMessagesAndCloses() : void{
		$fixture = new IdentityFixture();
		$config = new TransportConfig(maxMessageBytes: 512);
		$listener = new RecordingListener();
		$transport = self::transport($config, $fixture, $listener);
		$client = new ExtRtcPeer($config);
		try{
			$id = $transport->accept('native-network', $fixture->offer(self::offer($client), time()));
			$listener->answered = function(int $answerId) use ($listener, $client, $config) : void{
				$answer = SdpIdentity::fromSdp($listener->answers[$answerId], $config);
				self::assertSame('operator.test', $answer->providerDomain);
				self::assertNotNull($answer->token);
				$client->setRemoteAnswer($answer->sdpWithoutIdentity);
			};
			ExtRtcPeerTest::waitFor(function() use ($transport, $listener, $id) : bool{
				$transport->poll();
				return isset($listener->connections[$id]);
			});
			$connection = $listener->connections[$id];
			self::assertSame('player', $connection->getIdentity()->subject);
			self::assertSame(['answer', 'open'], $listener->events);
			ExtRtcPeerTest::waitFor(fn() => $client->isChannelOpen(Channel::RELIABLE) && $client->isChannelOpen(Channel::UNRELIABLE));
			$payload = str_repeat("\x00\xffabc", 400);
			$codec = new FrameCodec($config);
			foreach($codec->encode($payload, 512) as $frame){ self::assertTrue($client->sendFrame(Channel::RELIABLE, $frame)); }
			self::assertTrue($client->sendFrame(Channel::UNRELIABLE, "\0\xffunreliable"));
			ExtRtcPeerTest::waitFor(function() use ($transport, $listener) : bool{ $transport->poll(); return count($listener->payloads) === 2; });
			self::assertContains([$id, $payload, Channel::RELIABLE], $listener->payloads);
			self::assertContains([$id, "\xffunreliable", Channel::UNRELIABLE], $listener->payloads);
			$accepted = [];
			self::assertSame(SendResult::ACCEPTED, $connection->send($payload, accepted: function(bool $ok) use (&$accepted) : void{ $accepted[] = $ok; }));
			self::assertSame(SendResult::ACCEPTED, $connection->send('lossy', Channel::UNRELIABLE));
			$received = null;
			$lossy = null;
			ExtRtcPeerTest::waitFor(function() use ($transport, $client, $codec, &$received, &$lossy) : bool{
				$transport->poll();
				while(($frame = $client->receiveFrame(Channel::RELIABLE)) !== null){
					$received = $codec->receive($frame, Channel::RELIABLE, 512, hrtime(true) / 1_000_000_000);
				}
				$lossy ??= $client->receiveFrame(Channel::UNRELIABLE);
				return $received !== null && $lossy !== null;
			});
			self::assertSame($payload, $received);
			self::assertSame("\0lossy", $lossy);
			self::assertSame([true], $accepted);
			$transport->stop();
			self::assertSame(ConnectionState::CLOSED, $connection->getState());
			self::assertSame(['answer', 'open', 'close'], $listener->events);
			self::assertSame('local_close', $listener->closed[0][1]);
			ExtRtcPeerTest::waitFor(fn() => RtcRuntime::getStats()['activePeers'] === 1);
		}finally{
			$transport->stop();
			$client->close();
		}
	}

	public function testRemoteDisconnectClosesConnectionAndReleasesNativePeer() : void{
		$fixture = new IdentityFixture();
		$config = new TransportConfig();
		$listener = new RecordingListener();
		$transport = self::transport($config, $fixture, $listener);
		$client = new ExtRtcPeer($config);
		try{
			$id = $transport->accept('disconnect', $fixture->offer(self::offer($client), time()));
			$listener->answered = function(int $answerId) use ($listener, $client, $config) : void{
				$client->setRemoteAnswer(SdpIdentity::fromSdp($listener->answers[$answerId], $config)->sdpWithoutIdentity);
			};
			ExtRtcPeerTest::waitFor(function() use ($transport, $listener, $id) : bool{ $transport->poll(); return isset($listener->connections[$id]); });
			$client->close();
			ExtRtcPeerTest::waitFor(function() use ($transport, $listener) : bool{ $transport->poll(); return $listener->closed !== []; });
			self::assertContains($listener->closed[0][1], ['closed', 'backend_failed']);
			self::assertSame(ConnectionState::CLOSED, $listener->connections[$id]->getState());
			self::assertSame(0, RtcRuntime::getStats()['activePeers']);
		}finally{
			$transport->stop();
			$client->close();
		}
	}

	public function testNativeUnexpectedChannelFailsBeforeOpen() : void{
		$fixture = new IdentityFixture();
		$config = new TransportConfig();
		$listener = new RecordingListener();
		$transport = self::transport($config, $fixture, $listener);
		$client = new PeerConnection(PeerConnectionOptions::create());
		$channels = [];
		try{
			// dropping an ext-rtc channel handle closes the channel
			$channels = [$client->createDataChannel('ReliableDataChannel'), $client->createDataChannel('unexpected')];
			ExtRtcPeerTest::waitFor(fn() => $client->getGatheringState() === GatheringState::COMPLETE);
			$transport->accept('bad-channel', $fixture->offer($client->getLocalDescription() ?? self::fail('Missing offer'), time()));
			$listener->answered = function(int $id) use ($client, $listener, $config) : void{
				$client->setRemoteAnswer(SdpIdentity::fromSdp($listener->answers[$id], $config)->sdpWithoutIdentity);
			};
			ExtRtcPeerTest::waitFor(function() use ($transport, $listener) : bool{ $transport->poll(); return $listener->closed !== []; });
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
			$transport = self::transport($config, $fixture, $listener);
			$clients = [];
			try{
				for($index = 0; $index < 2; ++$index){
					$client = new ExtRtcPeer($config);
					$clients[$index + 1] = $client;
					$transport->accept('client-' . $index, $fixture->offer(self::offer($client), time()));
				}
				$listener->answered = static function(int $id) use ($clients, $listener, $config) : void{
					$clients[$id]->setRemoteAnswer(SdpIdentity::fromSdp($listener->answers[$id], $config)->sdpWithoutIdentity);
				};
				ExtRtcPeerTest::waitFor(function() use ($transport, $listener) : bool{ $transport->poll(); return count($listener->connections) === 2; });
				foreach($listener->connections as $id => $connection){
					self::assertSame(SendResult::ACCEPTED, $connection->send("peer\x00$id", immediate: true));
				}
				foreach($clients as $id => $client){
					ExtRtcPeerTest::waitFor(fn() => $client->peekFrame(Channel::RELIABLE) !== null);
					self::assertSame("\0peer\x00$id", $client->receiveFrame(Channel::RELIABLE));
				}
				$transport->stop();
				self::assertCount(2, $listener->closed);
				foreach($listener->connections as $connection){ self::assertSame(ConnectionState::CLOSED, $connection->getState()); }
				self::assertSame(2, RtcRuntime::getStats()['activePeers']);
			}finally{
				$transport->stop();
				foreach($clients as $client){ $client->close(); }
			}
		}
	}
}
