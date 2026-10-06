<?php

declare(strict_types=1);

namespace amber\nethernet\tests\identity;

use amber\nethernet\TransportConfig;
use amber\nethernet\TransportException;
use amber\nethernet\identity\SdpIdentity;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SdpIdentityTest extends TestCase{
	private const DIGEST = 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99';
	private const FINGERPRINT = 'a=fingerprint:sha-256 ' . self::DIGEST;
	private const TOKEN = 'e30.e30.c2ln';
	private const JWS = 'eyJhbGciOiJFUzM4NCJ9..c2ln';

	/** @param array<string, mixed> $fields */
	private static function envelope(array $fields) : string{
		return base64_encode(json_encode($fields, JSON_THROW_ON_ERROR));
	}

	private static function validEnvelope() : string{
		return self::envelope(['idp' => ['domain' => 'partner.example', 'protocol' => 'default'], 'assertion' => '{"token":"e30.e30.c2ln","fingerprints":"eyJhbGciOiJFUzM4NCJ9..c2ln"}']);
	}

	public function testCanonicalGoldenPayloadAndExactIdentityRemoval() : void{
		$clean = "v=0\r\ns=-\r\n" . self::FINGERPRINT . "\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
		$offer = str_replace("m=application", 'a=identity:' . self::validEnvelope() . "\r\nm=application", $clean);
		$identity = SdpIdentity::fromSdp($offer, new TransportConfig());
		self::assertSame($clean, $identity->sdpWithoutIdentity);
		self::assertSame('{"fingerprint":[{"algorithm":"sha-256","digest":"' . self::DIGEST . '"}]}', $identity->canonicalFingerprints);
		self::assertSame(self::TOKEN, $identity->token);
		self::assertSame(self::JWS, $identity->detachedJws);
		self::assertSame('partner.example', $identity->providerDomain);
	}

	public function testMissingIdentityIsRepresentationNotAuthentication() : void{
		$sdp = "v=0\n" . self::FINGERPRINT . "\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\n";
		$identity = SdpIdentity::fromSdp($sdp, new TransportConfig());
		self::assertNull($identity->token);
		self::assertNull($identity->detachedJws);
		self::assertSame($sdp, $identity->sdpWithoutIdentity);
	}

	public function testFingerprintOrderAndCaseArePreservedAcrossScopes() : void{
		$lower = strtolower(self::DIGEST);
		$sdp = "v=0\n" . self::FINGERPRINT . "\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\na=fingerprint:sha-256 $lower\n";
		$identity = SdpIdentity::fromSdp($sdp, new TransportConfig());
		self::assertSame('{"fingerprint":[{"algorithm":"sha-256","digest":"' . self::DIGEST . '"},{"algorithm":"sha-256","digest":"' . $lower . '"}]}', $identity->canonicalFingerprints);
	}

	/** @return iterable<string, array{string}> */
	public static function malformedSdp() : iterable{
		$base = "v=0\n" . self::FINGERPRINT . "\n";
		$tail = "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\n";
		$valid = 'a=identity:' . self::validEnvelope() . "\n";
		yield 'duplicate identity' => [$base . $valid . $valid . $tail];
		yield 'identity in media section' => [$base . $tail . $valid];
		yield 'duplicate scope fingerprint' => [$base . self::FINGERPRINT . "\n" . $tail];
		yield 'missing fingerprint' => ["v=0\n" . $tail];
		yield 'short digest' => ["v=0\na=fingerprint:sha-256 AA:BB\n" . $tail];
		yield 'invalid hex' => [str_replace('AA:BB', 'GG:BB', $base) . $tail];
		yield 'unsupported hash' => [str_replace('sha-256', 'md5', $base) . $tail];
		yield 'attribute without colon' => [$base . "a=identity\n" . $tail];
		yield 'embedded NUL' => [$base . "s=\0\n" . $tail];
		yield 'bare CR' => [$base . "s=x\rs=y\n" . $tail];
		yield 'invalid UTF8' => [$base . "s=\xff\n" . $tail];
		yield 'invalid base64' => [$base . "a=identity:***\n" . $tail];
		yield 'bad outer JSON' => [$base . 'a=identity:' . base64_encode('{') . "\n" . $tail];
		yield 'outer array' => [$base . 'a=identity:' . base64_encode('[]') . "\n" . $tail];
		yield 'duplicate outer key' => [$base . 'a=identity:' . base64_encode('{"idp":{},"idp":{},"assertion":"x"}') . "\n" . $tail];
		yield 'escaped duplicate key' => [$base . 'a=identity:' . base64_encode('{"idp":{"domain":"x","\u0064omain":"y","protocol":"default"},"assertion":"x"}') . "\n" . $tail];
		foreach([
			'missing idp' => ['assertion' => '{}'],
			'wrong protocol' => ['idp' => ['domain' => 'x', 'protocol' => 'other'], 'assertion' => '{}'],
			'domain is not a string' => ['idp' => ['domain' => 1, 'protocol' => 'default'], 'assertion' => '{}'],
			'assertion is not a string' => ['idp' => ['domain' => 'x', 'protocol' => 'default'], 'assertion' => []],
			'bad assertion JSON' => ['idp' => ['domain' => 'x', 'protocol' => 'default'], 'assertion' => '{'],
			'duplicate assertion key' => ['idp' => ['domain' => 'x', 'protocol' => 'default'], 'assertion' => '{"token":"a","token":"b","fingerprints":"c"}'],
			'bad token format' => ['idp' => ['domain' => 'x', 'protocol' => 'default'], 'assertion' => '{"token":"a","fingerprints":"' . self::JWS . '"}'],
			'JWS includes payload' => ['idp' => ['domain' => 'x', 'protocol' => 'default'], 'assertion' => '{"token":"' . self::TOKEN . '","fingerprints":"e30.e30.c2ln"}'],
			'JWS invalid base64url' => ['idp' => ['domain' => 'x', 'protocol' => 'default'], 'assertion' => '{"token":"' . self::TOKEN . '","fingerprints":"***..c2ln"}'],
		] as $name => $fields){
			yield $name => [$base . 'a=identity:' . self::envelope($fields) . "\n" . $tail];
		}
	}

	#[DataProvider('malformedSdp')]
	public function testMalformedRepresentationIsRejected(string $sdp) : void{
		$this->expectException(TransportException::class);
		SdpIdentity::fromSdp($sdp, new TransportConfig());
	}

	public function testSdpByteLimit() : void{
		$this->expectException(TransportException::class);
		SdpIdentity::fromSdp("v=0\n" . self::FINGERPRINT, new TransportConfig(maxSdpBytes: 32));
	}

	public function testDecodedIdentityByteLimit() : void{
		$this->expectException(TransportException::class);
		SdpIdentity::fromSdp("v=0\n" . self::FINGERPRINT . "\na=identity:" . self::validEnvelope(), new TransportConfig(maxIdentityBytes: 8));
	}

	public function testCandidateLimitBeforeNativeParsing() : void{
		$this->expectException(TransportException::class);
		SdpIdentity::fromSdp("v=0\n" . self::FINGERPRINT . "\na=candidate:1\na=candidate:2\n", new TransportConfig(maxCandidates: 1));
	}

	public function testLongValidJsonStringRemainsSupported() : void{
		$envelope = self::envelope([
			'padding' => str_repeat('a', 10000),
			'idp' => ['domain' => 'partner.example', 'protocol' => 'default'],
			'assertion' => '{"token":"' . self::TOKEN . '","fingerprints":"' . self::JWS . '"}'
		]);
		$identity = SdpIdentity::fromSdp("v=0\n" . self::FINGERPRINT . "\na=identity:" . $envelope, new TransportConfig());
		self::assertSame('partner.example', $identity->providerDomain);
	}

	/** @return iterable<string, array{string}> */
	public static function duplicateKeysAfterLongString() : iterable{
		yield 'literal duplicate' => ['domain'];
		yield 'escaped duplicate' => ['\\u0064omain'];
	}

	#[DataProvider('duplicateKeysAfterLongString')]
	public function testDuplicateKeysAfterLongStringAreRejected(string $duplicateKey) : void{
		$json = '{"padding":"' . str_repeat('a', 10000) . '","idp":{"domain":"a","' . $duplicateKey . '":"b","protocol":"default"},"assertion":"{\\"token\\":\\"' . self::TOKEN . '\\",\\"fingerprints\\":\\"' . self::JWS . '\\"}"}';
		$this->expectException(TransportException::class);
		SdpIdentity::fromSdp("v=0\n" . self::FINGERPRINT . "\na=identity:" . base64_encode($json), new TransportConfig());
	}
}
