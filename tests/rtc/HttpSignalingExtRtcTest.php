<?php

declare(strict_types=1);

namespace amber\nethernet\tests\rtc;

use amber\nethernet\backend\ExtRtcPeer;
use amber\nethernet\backend\WebRtcPeer;
use amber\nethernet\Channel;
use amber\nethernet\ConnectionState;
use amber\nethernet\identity\ClientServerIdentityHandler;
use amber\nethernet\identity\SdpIdentity;
use amber\nethernet\signaling\HttpSignaling;
use amber\nethernet\signaling\ServerMetadata;
use amber\nethernet\tests\identity\IdentityFixture;
use amber\nethernet\tests\signaling\AnswerSignatures;
use amber\nethernet\tests\transport\RecordingListener;
use amber\nethernet\Transport;
use amber\nethernet\TransportConfig;
use amber\rtc\RtcRuntime;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class HttpSignalingExtRtcTest extends TestCase{
	protected function tearDown() : void{
		ExtRtcPeerTest::waitFor(static fn() => RtcRuntime::getStats()['activePeers'] === 0 && RtcRuntime::getStats()['activeChannels'] === 0);
	}

	/** @return iterable<string, array{bool}> */
	public static function factories() : iterable{
		yield 'default transport backend' => [false];
		yield 'fixed-port udp mux' => [true];
	}

	#[DataProvider('factories')]
	public function testFullIceHttpExchangeThenPayloadsBothWays(bool $mux) : void{
		$fixture = new IdentityFixture();
		$config = new TransportConfig(maxMessageBytes: 512);
		$listener = new RecordingListener();
		$http = new HttpSignaling($config, static fn() => new ServerMetadata('Test', 1, 'fixture', 'World', 0, 1, 0), $listener);
		$port = ExtRtcPeerTest::freeUdpPort();
		$transport = new Transport($config, new ClientServerIdentityHandler($fixture->verifier(), $fixture->server), $http,
			$mux ? static fn() : WebRtcPeer => new ExtRtcPeer($config, $port, $port, '127.0.0.1', true) : null);
		$http->bind($transport);
		$client = new ExtRtcPeer($config, 0, 0, '127.0.0.1');
		try{
			$client->createChannel(Channel::RELIABLE);
			$client->createChannel(Channel::UNRELIABLE);
			ExtRtcPeerTest::waitFor(fn() => $client->isGatheringComplete());
			$offer = $fixture->offer($client->getLocalDescription() ?? self::fail('Missing offer'), time());
			$exchange = $http->open();
			$wire = "POST /v1/join/rtc-opaque HTTP/1.1\r\nHost: test\r\nContent-Type: application/sdp\r\nContent-Length: " . strlen($offer) . "\r\n\r\n" . $offer;
			foreach(str_split($wire, 37) as $bytes){ $http->receive($exchange, $bytes); }
			$id = $http->getTransportId($exchange);
			self::assertNotNull($id);
			$response = null;
			ExtRtcPeerTest::waitFor(function() use ($http, $transport, $exchange, &$response) : bool{
				$transport->poll();
				$response = $http->takeResponse($exchange);
				return $response !== null;
			});
			self::assertNotNull($response);
			self::assertSame(200, $response->status);
			self::assertSame('application/sdp', $response->contentType);
			self::assertSame(1, substr_count($response->body, 'a=identity:'));
			$parsed = SdpIdentity::fromSdp($response->body, $config);
			AnswerSignatures::verify($parsed);
			if($mux){ self::assertSame(['127.0.0.1:' . $port], ExtRtcPeerTest::hostCandidates($parsed->sdpWithoutIdentity)); }
			$client->setRemoteAnswer($parsed->sdpWithoutIdentity);
			$http->finish($exchange);
			$http->stop();
			ExtRtcPeerTest::waitFor(function() use ($transport, $listener, $id, $client) : bool{
				$transport->poll();
				return isset($listener->connections[$id]) && $client->isChannelOpen(Channel::RELIABLE) && $client->isChannelOpen(Channel::UNRELIABLE);
			});
			$connection = $listener->connections[$id];
			self::assertSame(2, RtcRuntime::getStats()['activePeers']);
			self::assertSame(ConnectionState::OPEN, $connection->getState());
			self::assertSame('rtc-opaque', $connection->getNetworkId());
			self::assertSame('player', $connection->getIdentity()->subject);
			self::assertTrue($client->sendFrame(Channel::UNRELIABLE, "\0payload"));
			self::assertTrue($client->sendFrame(Channel::RELIABLE, "\0reliable\x00\xff"));
			ExtRtcPeerTest::waitFor(function() use ($transport, $listener) : bool{ $transport->poll(); return count($listener->payloads) === 2; });
			self::assertEqualsCanonicalizing([[$id, 'payload', Channel::UNRELIABLE], [$id, "reliable\x00\xff", Channel::RELIABLE]], $listener->payloads);
			$connection->send("back\x00", immediate: true);
			ExtRtcPeerTest::waitFor(function() use ($transport, $client) : bool{ $transport->poll(); return $client->peekFrame(Channel::RELIABLE) !== null; });
			self::assertSame("\0back\x00", $client->receiveFrame(Channel::RELIABLE));
		}finally{
			$http->stop();
			$transport->stop();
			$client->close();
		}
	}
}
