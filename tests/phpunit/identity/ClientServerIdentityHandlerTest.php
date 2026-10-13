<?php

declare(strict_types=1);

namespace amber\nethernet\tests\identity;

use amber\nethernet\identity\ClientServerIdentityHandler;
use amber\nethernet\identity\PeerIdentity;
use amber\nethernet\identity\SdpIdentity;
use amber\nethernet\TransportConfig;
use amber\nethernet\TransportException;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

final class ClientServerIdentityHandlerTest extends TestCase{
	public function testAuthenticatesAndCompletesOnceWithRealSignatures() : void{
		$fixture = new IdentityFixture();
		$sdp = "v=0\r\na=fingerprint:sha-256 " . implode(':', array_fill(0, 32, 'AB')) . "\r\n";
		$identity = SdpIdentity::fromSdp($fixture->offer($sdp), new TransportConfig());
		$handler = new ClientServerIdentityHandler($fixture->verifier(), $fixture->server, clock: fn() => 1000);
		$calls = 0;
		$cancel = $handler->verifyClient($identity->token ?? '', $identity->canonicalFingerprints, $identity->detachedJws ?? '', function(?PeerIdentity $peer, ?TransportException $error) use (&$calls) : void{
			++$calls;
			self::assertNull($error);
			self::assertSame('player', $peer?->subject);
		});
		$cancel();
		$cancel();
		self::assertSame(1, $calls);
		$answer = SdpIdentity::fromSdp("v=0\r\na=identity:" . $handler->signServer($identity->canonicalFingerprints, 1000) . "\r\n" . substr($sdp, 5), new TransportConfig());
		self::assertSame('operator.test', $answer->providerDomain);
	}

	public function testMalformedAssertionCompletesWithError() : void{
		$fixture = new IdentityFixture();
		$handler = new ClientServerIdentityHandler($fixture->verifier(), $fixture->server);
		$calls = 0;
		$handler->verifyClient('bad', '{}', 'bad', function(?PeerIdentity $peer, ?TransportException $error) use (&$calls) : void{
			++$calls;
			self::assertNull($peer);
			self::assertSame('identity_invalid', $error?->errorCode);
		});
		self::assertSame(1, $calls);
	}

	public function testConsumerExceptionIsNotCompletedAgain() : void{
		$fixture = new IdentityFixture();
		$handler = new ClientServerIdentityHandler($fixture->verifier(), $fixture->server);
		$calls = 0;
		try{
			$handler->verifyClient('bad', '{}', 'bad', function() use (&$calls) : void{
				++$calls;
				throw new \LogicException('consumer');
			});
			self::fail('Consumer exception was swallowed');
		}catch(\LogicException $error){
			self::assertSame('consumer', $error->getMessage());
		}
		self::assertSame(1, $calls);
	}

	/** @return iterable<string, array{string}> */
	public static function failures() : iterable{
		yield 'expired' => ['expired'];
		yield 'untrusted' => ['untrusted'];
		yield 'signature' => ['signature'];
		yield 'limit' => ['limit'];
		yield 'noncanonical' => ['noncanonical'];
	}

	#[DataProvider('failures')]
	public function testRejectsUnsafeAssertions(string $case) : void{
		$fixture = new IdentityFixture();
		$sdp = "v=0\r\na=fingerprint:sha-256 " . implode(':', array_fill(0, 32, 'AB')) . "\r\n";
		$identity = SdpIdentity::fromSdp($fixture->offer($sdp), new TransportConfig());
		$verifier = $case === 'untrusted' ? new \amber\nethernet\identity\ClientIdentityVerifier(fn(?string $kid) => null, 'issuer', 'game') : $fixture->verifier();
		$config = $case === 'limit' ? new TransportConfig(maxIdentityBytes: 10) : new TransportConfig();
		$handler = new ClientServerIdentityHandler($verifier, $fixture->server, $config, fn() => $case === 'expired' ? 1060 : 1000);
		$canonical = $case === 'noncanonical' ? ' ' . $identity->canonicalFingerprints : $identity->canonicalFingerprints;
		$jws = $case === 'signature' ? substr($identity->detachedJws ?? '', 0, -4) . 'AAAA' : $identity->detachedJws ?? '';
		$calls = 0;
		$handler->verifyClient($identity->token ?? '', $canonical, $jws, function(?PeerIdentity $peer, ?TransportException $error) use (&$calls, $case) : void{
			++$calls;
			self::assertNull($peer);
			self::assertSame(match($case){
				'expired' => 'identity_expired', 'untrusted' => 'identity_untrusted',
				'signature' => 'identity_signature_invalid', default => 'identity_invalid'
			}, $error?->errorCode);
		});
		self::assertSame(1, $calls);
	}
}
