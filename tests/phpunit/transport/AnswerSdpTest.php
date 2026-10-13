<?php

declare(strict_types=1);

namespace amber\nethernet\tests\transport;

use amber\nethernet\identity\ClientServerIdentityHandler;
use amber\nethernet\identity\SdpIdentity;
use amber\nethernet\tests\identity\IdentityFixture;
use amber\nethernet\tests\signaling\AnswerSignatures;
use amber\nethernet\Transport;
use amber\nethernet\TransportConfig;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AnswerSdpTest extends TestCase{
	private const SESSION = "v=0\r\no=rtc 123456 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\na=fingerprint:sha-256 " . FakePeer::DIGEST . "\r\n";
	private const MEDIA = "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 127.0.0.1\r\na=mid:0\r\na=setup:active\r\na=sctp-port:5000\r\na=ice-ufrag:test\r\na=ice-pwd:abcdefghijklmnopqrstuvwx\r\na=candidate:1 1 UDP 2114977791 127.0.0.1 1234 typ host\r\na=end-of-candidates\r\n";

	/** @return iterable<string, array{string}> */
	public static function validAnswers() : iterable{
		yield 'native shape' => [self::SESSION . self::MEDIA];
		yield 'LF' => [str_replace("\r\n", "\n", self::SESSION . self::MEDIA)];
		yield 'mixed line endings' => [self::SESSION . str_replace("\r\n", "\n", self::MEDIA)];
		yield 'matching media fingerprint' => [self::SESSION . self::MEDIA . 'a=fingerprint:sha-256 ' . strtolower(FakePeer::DIGEST) . "\r\n"];
		yield 'optional session fields and repeated time' => [str_replace("s=-\r\nt=0 0", "s=-\r\ni=info\r\nu=https://example.test\r\ne=operator@example.test\r\np=+1 555 555\r\nc=IN IP4 127.0.0.1\r\nb=AS:100\r\nt=1 2\r\nr=7d 1h 0\r\nt=3 4\r\nz=1 -1h\r\nk=prompt", self::SESSION) . self::MEDIA];
	}

	#[DataProvider('validAnswers')]
	public function testSignedIdentityFollowsSessionFingerprintsAndPreservesAllBytes(string $sdp) : void{
		$fixture = new IdentityFixture();
		$config = new TransportConfig();
		$peer = new FakePeer();
		$peer->localSdp = $sdp;
		$listener = new RecordingListener();
		$transport = new Transport($config, new ClientServerIdentityHandler($fixture->verifier(), $fixture->server, clock: fn() => 1000), $listener, fn() => $peer, fn() => 0.0, fn() => 1000);
		try{
			$id = $transport->accept('id', $fixture->offer(self::SESSION . self::MEDIA));
			$transport->poll();
			$transport->poll();
			$answer = $listener->answers[$id];
			$identityOffset = strpos($answer, 'a=identity:');
			$mediaOffset = strpos($answer, 'm=');
			$fingerprintOffset = strpos($answer, 'a=fingerprint:');
			self::assertNotFalse($identityOffset);
			self::assertNotFalse($mediaOffset);
			self::assertNotFalse($fingerprintOffset);
			self::assertGreaterThan($fingerprintOffset, $identityOffset);
			self::assertLessThan($mediaOffset, $identityOffset);
			self::assertSame(1, substr_count($answer, 'a=identity:'));
			$originalMedia = strpos($sdp, 'm=');
			self::assertNotFalse($originalMedia);
			self::assertSame(substr($sdp, 0, $originalMedia), substr($answer, 0, $identityOffset));
			self::assertSame(substr($sdp, $originalMedia), substr($answer, $mediaOffset));
			$parsed = SdpIdentity::fromSdp($answer, $config);
			self::assertSame($sdp, $parsed->sdpWithoutIdentity);
			self::assertSame(SdpIdentity::fromSdp($sdp, $config)->canonicalFingerprints, $parsed->canonicalFingerprints);
			AnswerSignatures::verify($parsed);
		}finally{
			$transport->stop();
		}
	}

	/** @return iterable<string, array{string}> */
	public static function invalidAnswers() : iterable{
		$base = self::SESSION . self::MEDIA;
		yield 'missing origin' => [str_replace("o=rtc 123456 0 IN IP4 127.0.0.1\r\n", '', $base)];
		yield 'missing session name' => [str_replace("s=-\r\n", '', $base)];
		yield 'missing time' => [str_replace("t=0 0\r\n", '', $base)];
		yield 'time after attributes' => [str_replace("t=0 0\r\n", '', self::SESSION) . "t=0 0\r\n" . self::MEDIA];
		yield 'duplicate origin' => [str_replace("s=-", "o=rtc 123456 0 IN IP4 127.0.0.1\r\ns=-", $base)];
		yield 'empty origin' => [str_replace('o=rtc 123456 0 IN IP4 127.0.0.1', 'o=', $base)];
		yield 'invalid origin' => [str_replace('o=rtc 123456 0 IN IP4 127.0.0.1', 'o=invalid', $base)];
		yield 'invalid time' => [str_replace('t=0 0', 't=-1 0', $base)];
		yield 'no media boundary' => [self::SESSION];
		yield 'malformed media boundary' => [self::SESSION . "m=invalid\r\n"];
		yield 'only media fingerprint' => ["v=0\r\no=rtc 1 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n" . self::MEDIA . 'a=fingerprint:sha-256 ' . FakePeer::DIGEST . "\r\n"];
		yield 'conflicting media certificate' => [$base . 'a=fingerprint:sha-256 ' . str_repeat('CD:', 31) . "CD\r\n"];
		yield 'duplicate session fingerprint' => [self::SESSION . 'a=fingerprint:sha-256 ' . FakePeer::DIGEST . "\r\n" . self::MEDIA];
		yield 'session field inside media' => [$base . "t=0 0\r\n"];
		yield 'malformed line' => [$base . "not-an-sdp-field\r\n"];
		yield 'empty name' => [str_replace('s=-', 's=', $base)];
	}

	#[DataProvider('invalidAnswers')]
	public function testMalformedOrAmbiguousAnswerClosesWithoutEmission(string $sdp) : void{
		$fixture = new IdentityFixture();
		$config = new TransportConfig();
		$peer = new FakePeer();
		$peer->localSdp = $sdp;
		$listener = new RecordingListener();
		$transport = new Transport($config, new ClientServerIdentityHandler($fixture->verifier(), $fixture->server, clock: fn() => 1000), $listener, fn() => $peer, fn() => 0.0, fn() => 1000);
		try{
			$transport->accept('id', $fixture->offer(self::SESSION . self::MEDIA));
			$transport->poll();
			$transport->poll();
			self::assertSame([], $listener->answers);
			self::assertSame(['close'], $listener->events);
			self::assertSame('invalid_sdp', $listener->closed[0][1]);
			self::assertSame(1, $peer->closes);
			$transport->poll();
			self::assertCount(1, $listener->closed);
		}finally{
			$transport->stop();
		}
	}
}
