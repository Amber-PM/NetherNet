<?php

declare(strict_types=1);

namespace amber\nethernet\tests\native;

use amber\nethernet\backend\ExtWebRtcPeer;
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
use PHPUnit\Framework\TestCase;

final class HttpSignalingNativeTest extends TestCase{
	/** @param \Closure(): bool $condition */
	private static function waitFor(\Closure $condition) : void{
		$deadline = hrtime(true) + 10_000_000_000;
		while(!$condition()){
			if(hrtime(true) >= $deadline){ self::fail('Native signaling did not finish'); }
			usleep(1000);
		}
	}

	public function testFullIceHttpExchangeThenNativePayloadAndIndependentLifetime() : void{
		$fixture = new IdentityFixture();
		$config = new TransportConfig();
		$listener = new RecordingListener();
		$http = new HttpSignaling($config, static fn() => new ServerMetadata('Test', 1, 'fixture', 'World', 0, 1, 0), $listener);
		$server = null;
		$transport = new Transport($config, new ClientServerIdentityHandler($fixture->verifier(), $fixture->server), $http, function() use ($config, &$server) : ExtWebRtcPeer{ return $server = new ExtWebRtcPeer($config); });
		$http->bind($transport);
		$client = new ExtWebRtcPeer($config);
		try{
			$client->createChannel(Channel::RELIABLE);
			$client->createChannel(Channel::UNRELIABLE);
			self::waitFor(fn() => $client->isGatheringComplete());
			$sdp = $client->getLocalDescription();
			self::assertNotNull($sdp);
			$offer = $fixture->offer($sdp, time());
			$exchange = $http->open();
			$wire = "POST /v1/join/native-opaque HTTP/1.1\r\nHost: test\r\nContent-Type: application/sdp\r\nContent-Length: " . strlen($offer) . "\r\n\r\n" . $offer;
			foreach(str_split($wire, 37) as $bytes){ $http->receive($exchange, $bytes); }
			$id = $http->getTransportId($exchange);
			self::assertNotNull($id);
			$response = null;
			self::waitFor(function() use ($http, $transport, $exchange, &$response) : bool{
				$transport->poll();
				$response = $http->takeResponse($exchange);
				return $response !== null;
			});
			self::assertNotNull($response);
			self::assertSame(200, $response->status);
			self::assertSame('application/sdp', $response->contentType);
			self::assertStringContainsString('a=candidate:', $response->body);
			self::assertMatchesRegularExpression('/\Av=0\r\no=[^\r\n]+\r\ns=[^\r\n]+\r\nt=[0-9]+ [0-9]+\r\n/', $response->body);
			self::assertMatchesRegularExpression('/\r\na=fingerprint:[^\r\n]+\r\na=identity:[^\r\n]+\r\nm=application /', $response->body);
			self::assertSame(1, substr_count($response->body, 'a=identity:'));
			$parsed = SdpIdentity::fromSdp($response->body, $config);
			self::assertNotNull($server);
			$base = $server->getLocalDescription();
			self::assertNotNull($base);
			self::assertSame($base, $parsed->sdpWithoutIdentity);
			self::assertSame(SdpIdentity::fromSdp($base, $config)->canonicalFingerprints, $parsed->canonicalFingerprints);
			AnswerSignatures::verify($parsed);
			$client->setRemoteAnswer($parsed->sdpWithoutIdentity);
			$http->finish($exchange);
			$http->stop();
			// The server's onOpen can precede the client's DCEP acknowledgement.
			self::waitFor(function() use ($transport, $listener, $id, $client) : bool{
				$transport->poll();
				return isset($listener->connections[$id]) && $client->isChannelOpen(Channel::RELIABLE) && $client->isChannelOpen(Channel::UNRELIABLE);
			});
			self::assertSame(ConnectionState::OPEN, $listener->connections[$id]->getState());
			self::assertSame('native-opaque', $listener->connections[$id]->getNetworkId());
			self::assertTrue($client->sendFrame(Channel::UNRELIABLE, "\0payload"));
			self::waitFor(function() use ($transport, $listener) : bool{ $transport->poll(); return $listener->payloads !== []; });
			self::assertSame([[$id, 'payload', Channel::UNRELIABLE]], $listener->payloads);
		}finally{
			$http->stop();
			$transport->stop();
			$client->close();
		}
	}
}
