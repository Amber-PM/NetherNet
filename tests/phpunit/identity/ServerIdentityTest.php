<?php

declare(strict_types=1);

namespace amber\nethernet\tests\identity;

use amber\nethernet\identity\SdpIdentity;
use amber\nethernet\identity\ServerIdentity;
use amber\nethernet\TransportConfig;
use amber\nethernet\TransportException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ServerIdentityTest extends TestCase{
	private static \OpenSSLAsymmetricKey $key;
	private const DIGEST = 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99';
	private const PAYLOAD = '{"fingerprint":[{"algorithm":"sha-256","digest":"' . self::DIGEST . '"}]}';

	public static function setUpBeforeClass() : void{
		self::$key = self::key();
	}

	private static function key(string $curve = 'secp384r1') : \OpenSSLAsymmetricKey{
		$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curve, 'config' => __DIR__ . '/openssl.cnf']);
		self::assertNotFalse($key);
		return $key;
	}

	private static function url(string $bytes) : string{
		return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
	}

	private static function decode(string $encoded) : string{
		$bytes = base64_decode(strtr($encoded, '-_', '+/'), true);
		self::assertNotFalse($bytes);
		return $bytes;
	}

	private static function der(string $raw) : string{
		self::assertSame(96, strlen($raw));
		$body = '';
		foreach(str_split($raw, 48) as $scalar){
			$scalar = ltrim($scalar, "\0");
			if($scalar === '' || ord($scalar[0]) >= 128){
				$scalar = "\0" . $scalar;
			}
			$body .= "\x02" . chr(strlen($scalar)) . $scalar;
		}
		return "\x30" . chr(strlen($body)) . $body;
	}

	/** @return array{string, string} */
	private static function assertion(string $value) : array{
		self::assertDoesNotMatchRegularExpression('/[\r\n]/', $value);
		self::assertSame(base64_encode(self::decode($value)), $value);
		$envelope = json_decode(self::decode($value), true, 16, JSON_THROW_ON_ERROR);
		self::assertIsArray($envelope);
		self::assertSame(['domain' => 'operator.test', 'protocol' => 'default'], $envelope['idp']);
		self::assertIsString($envelope['assertion']);
		$assertion = json_decode($envelope['assertion'], true, 16, JSON_THROW_ON_ERROR);
		self::assertIsArray($assertion);
		self::assertIsString($assertion['token']);
		self::assertIsString($assertion['fingerprints']);
		return [$assertion['token'], $assertion['fingerprints']];
	}

	private static function verify(string $compact, string $payload, \OpenSSLAsymmetricKey $public) : int{
		$parts = explode('.', $compact);
		self::assertCount(3, $parts);
		self::assertSame(['alg' => 'ES384'], json_decode(self::decode($parts[0]), true, 16, JSON_THROW_ON_ERROR));
		$details = openssl_pkey_get_details($public);
		self::assertNotFalse($details);
		$verifyKey = openssl_pkey_get_public($details['key']);
		self::assertNotFalse($verifyKey);
		$result = openssl_verify($parts[0] . '.' . self::url($payload), self::der(self::decode($parts[2])), $verifyKey, OPENSSL_ALGO_SHA384);
		self::assertNotFalse($result);
		return $result;
	}

	public function testBothSignaturesUseTheEmbeddedPublicKeyAndBindTheExactFingerprints() : void{
		$signer = new ServerIdentity(self::$key, 'operator.test', 60, ['iss' => 'operator', 'aud' => ['bedrock'], 'sub' => 'fleet']);
		[$token, $jws] = self::assertion($signer->signServer(self::PAYLOAD, 1000));
		$parts = explode('.', $token);
		$claimsText = self::decode($parts[1]);
		$claims = json_decode($claimsText, true, 16, JSON_THROW_ON_ERROR);
		self::assertIsArray($claims);
		self::assertSame(1000, $claims['iat']);
		self::assertSame(1060, $claims['exp']);
		self::assertSame('operator', $claims['iss']);
		self::assertSame('fleet', $claims['sub']);
		self::assertSame(['bedrock'], $claims['aud']);
		self::assertIsArray($claims['cpk']);
		self::assertSame(['kty', 'crv', 'x', 'y'], array_keys($claims['cpk']));
		self::assertSame('EC', $claims['cpk']['kty']);
		self::assertSame('P-384', $claims['cpk']['crv']);
		self::assertIsString($claims['cpk']['x']);
		self::assertIsString($claims['cpk']['y']);
		$der = hex2bin('3076301006072a8648ce3d020106052b8104002203620004') . self::decode($claims['cpk']['x']) . self::decode($claims['cpk']['y']);
		$public = openssl_pkey_get_public("-----BEGIN PUBLIC KEY-----\n" . base64_encode($der) . "\n-----END PUBLIC KEY-----\n");
		self::assertNotFalse($public);
		$details = openssl_pkey_get_details(self::$key);
		self::assertNotFalse($details);
		$embedded = openssl_pkey_get_details($public);
		self::assertNotFalse($embedded);
		self::assertSame($details['key'], $embedded['key']);
		self::assertSame(1, self::verify($token, $claimsText, $public));
		self::assertSame('', explode('.', $jws)[1]);
		self::assertSame(1, self::verify($jws, self::PAYLOAD, $public));
		self::assertSame(0, self::verify($jws, str_replace('AA', 'aa', self::PAYLOAD), $public));
		self::assertSame(0, self::verify($token, str_replace('fleet', 'other', $claimsText), $public));
		self::assertSame(0, self::verify($token, str_replace('P-384', 'P-256', $claimsText), $public));
		self::assertSame(0, self::verify($token, $claimsText, self::key()));
		foreach([$token, $jws] as $compact){
			$p = explode('.', $compact);
			$signature = self::decode($p[2]);
			$signature[0] = chr(ord($signature[0]) ^ 1);
			$p[2] = self::url($signature);
			self::assertSame(0, self::verify(implode('.', $p), $compact === $token ? $claimsText : self::PAYLOAD, $public));
		}
	}

	public function testPemReloadPreservesIdentityAcrossInstancesAndTokenRotation() : void{
		self::assertTrue(openssl_pkey_export(self::$key, $pem, 'test-passphrase', ['config' => __DIR__ . '/openssl.cnf']));
		$first = new ServerIdentity($pem, 'operator.test', 60, [], 'test-passphrase');
		$second = new ServerIdentity($pem, 'operator.test', 120, [], 'test-passphrase');
		[$a] = self::assertion($first->signServer(self::PAYLOAD, 1000));
		[$b] = self::assertion($second->signServer(self::PAYLOAD, 2000));
		$ca = json_decode(self::decode(explode('.', $a)[1]), true, 16, JSON_THROW_ON_ERROR);
		$cb = json_decode(self::decode(explode('.', $b)[1]), true, 16, JSON_THROW_ON_ERROR);
		self::assertIsArray($ca);
		self::assertIsArray($cb);
		self::assertSame($ca['cpk'], $cb['cpk']);
		self::assertNotSame($ca['iat'], $cb['iat']);
		self::assertNotSame($ca['exp'], $cb['exp']);
	}

	public function testEnvelopeRoundTripsWithSessionAndMediaFingerprints() : void{
		$signer = new ServerIdentity(self::$key, 'operator.test');
		foreach(["a=fingerprint:sha-256 " . self::DIGEST . "\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n", "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=fingerprint:sha-256 " . self::DIGEST . "\r\n", "a=fingerprint:sha-256 " . self::DIGEST . "\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=fingerprint:sha-256 " . strtolower(self::DIGEST) . "\r\n"] as $tail){
			$sdp = "v=0\r\ns=-\r\nt=0 0\r\n" . $tail;
			$parsed = SdpIdentity::fromSdp($sdp, new TransportConfig());
			$value = $signer->signServer($parsed->canonicalFingerprints, 1000);
			$offset = strpos($sdp, 'm=');
			self::assertNotFalse($offset);
			$answer = substr($sdp, 0, $offset) . 'a=identity:' . $value . "\r\n" . substr($sdp, $offset);
			$roundTrip = SdpIdentity::fromSdp($answer, new TransportConfig());
			self::assertSame($sdp, $roundTrip->sdpWithoutIdentity);
			self::assertSame($parsed->canonicalFingerprints, $roundTrip->canonicalFingerprints);
			self::assertSame('operator.test', $roundTrip->providerDomain);
			self::assertNotNull($roundTrip->detachedJws);
			self::assertSame(1, self::verify($roundTrip->detachedJws, $roundTrip->canonicalFingerprints, self::$key));
		}
	}

	public function testRejectsPublicKeysAndOtherAlgorithms() : void{
		$details = openssl_pkey_get_details(self::$key);
		self::assertNotFalse($details);
		$public = openssl_pkey_get_public($details['key']);
		self::assertNotFalse($public);
		$rsa = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048, 'config' => __DIR__ . '/openssl.cnf']);
		self::assertNotFalse($rsa);
		foreach([$public, $rsa, self::key('prime256v1'), 'not a key', 'file:///missing/key.pem'] as $key){
			try{
				new ServerIdentity($key, 'operator.test');
				self::fail('Invalid key accepted');
			}catch(\InvalidArgumentException $e){
				self::assertStringNotContainsString('PRIVATE KEY', $e->getMessage());
			}
		}
	}

	/** @return iterable<string, array{string, int, array<string, mixed>}> */
	public static function invalidParameters() : iterable{
		foreach(['', 'https://operator.test', "operator.test\n", '-bad.test', 'bad_.test', 'bad..test', 'bad.test.', str_repeat('a', 64) . '.test', 'é.test'] as $domain){
			yield 'domain ' . bin2hex($domain) => [$domain, 60, []];
		}
		yield 'zero lifetime' => ['operator.test', 0, []];
		yield 'negative lifetime' => ['operator.test', -1, []];
		yield 'overflow lifetime' => ['operator.test', PHP_INT_MAX, []];
		foreach([['cpk' => []], ['iat' => 1], ['exp' => 1], ['iss' => ''], ['sub' => null], ['aud' => []], ['aud' => ['ok', 1]], ['nbf' => -1], ['nbf' => 1.5], ['nbf' => PHP_INT_MAX], ['custom' => INF], ['custom' => new \stdClass()], ['custom' => str_repeat('a', 8193)]] as $index => $claims){
			yield 'claims ' . $index => ['operator.test', 60, $claims];
		}
	}

	/** @param array<string, mixed> $claims */
	#[DataProvider('invalidParameters')]
	public function testRejectsInvalidParameters(string $domain, int $lifetime, array $claims) : void{
		$this->expectException(\InvalidArgumentException::class);
		new ServerIdentity(self::$key, $domain, $lifetime, $claims);
	}

	/** @return iterable<string, array{string, int}> */
	public static function invalidSigningInputs() : iterable{
		foreach(['', '{}', '{"fingerprint":[]}', '{"fingerprint":null}', '{"fingerprint":[],"fingerprint":[]}', str_replace('sha-256', 'sha-384', self::PAYLOAD), str_replace('AA:', '', self::PAYLOAD), ' ' . self::PAYLOAD, str_replace('"algorithm":"sha-256","digest"', '"digest":"sha-256","algorithm"', self::PAYLOAD), str_repeat('a', 65537)] as $index => $payload){
			yield 'payload ' . $index => [$payload, 1000];
		}
		yield 'negative time' => [self::PAYLOAD, -1];
		yield 'time overflow' => [self::PAYLOAD, PHP_INT_MAX];
		yield 'inexact sum' => [self::PAYLOAD, 9007199254740991];
	}

	#[DataProvider('invalidSigningInputs')]
	public function testRejectsInvalidSigningInputs(string $payload, int $now) : void{
		$signer = new ServerIdentity(self::$key, 'operator.test');
		$this->expectException(\InvalidArgumentException::class);
		$signer->signServer($payload, $now);
	}

	public function testNotBeforeAndExactTimeBoundary() : void{
		$signer = new ServerIdentity(self::$key, 'operator.test', 60, ['nbf' => 1000]);
		[$token] = self::assertion($signer->signServer(self::PAYLOAD, 1000));
		$claims = json_decode(self::decode(explode('.', $token)[1]), true, 16, JSON_THROW_ON_ERROR);
		self::assertIsArray($claims);
		self::assertSame(1000, $claims['nbf']);
		$this->expectException(\InvalidArgumentException::class);
		$signer->signServer(self::PAYLOAD, 999);
	}

	public function testExactMaximumExpiryAndEpochAreUsable() : void{
		$signer = new ServerIdentity(self::$key, 'operator.test');
		foreach([0, min(PHP_INT_MAX, 9007199254740991) - 60] as $now){
			[$token] = self::assertion($signer->signServer(self::PAYLOAD, $now));
			$claims = json_decode(self::decode(explode('.', $token)[1]), true, 16, JSON_THROW_ON_ERROR);
			self::assertIsArray($claims);
			self::assertSame($now, $claims['iat']);
			self::assertSame($now + 60, $claims['exp']);
		}
	}

	public function testWrongPemPassphraseFailsWithoutExposingSecret() : void{
		self::assertTrue(openssl_pkey_export(self::$key, $pem, 'actual-secret', ['config' => __DIR__ . '/openssl.cnf']));
		try{
			new ServerIdentity($pem, 'operator.test', 60, [], 'wrong-secret');
			self::fail('Wrong passphrase accepted');
		}catch(\InvalidArgumentException $e){
			self::assertStringNotContainsString('actual-secret', $e->getMessage());
			self::assertStringNotContainsString($pem, $e->getMessage());
			self::assertNull($e->getPrevious());
		}
	}

	public function testRejectsARealPrivateKeyWithAnUnrelatedPublicPoint() : void{
		$a = openssl_pkey_get_details(self::$key);
		$b = openssl_pkey_get_details(self::key());
		self::assertNotFalse($a);
		self::assertNotFalse($b);
		$der = hex2bin('3081a40201010430') . str_pad($a['ec']['d'], 48, "\0", STR_PAD_LEFT) . hex2bin('a00706052b81040022a16403620004') . str_pad($b['ec']['x'], 48, "\0", STR_PAD_LEFT) . str_pad($b['ec']['y'], 48, "\0", STR_PAD_LEFT);
		$pem = "-----BEGIN EC PRIVATE KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END EC PRIVATE KEY-----\n";
		$key = openssl_pkey_get_private($pem);
		self::assertNotFalse($key);
		foreach([$key, $pem] as $input){
			try{
				new ServerIdentity($input, 'operator.test');
				self::fail('Mismatched private and public components accepted');
			}catch(\InvalidArgumentException $e){
				self::assertStringNotContainsString($pem, $e->getMessage());
			}
		}
	}

	public function testIndependentVectorsConvertToTheirOriginalJoseBytes() : void{
		$fixture = json_decode((string) file_get_contents(__DIR__ . '/fixtures/es384.json'), true, 16, JSON_THROW_ON_ERROR);
		self::assertIsArray($fixture);
		self::assertIsArray($fixture['vectors']);
		$convert = new \ReflectionMethod(ServerIdentity::class, 'joseSignature');
		$signatures = [];
		foreach($fixture['vectors'] as $name => $vector){
			self::assertIsArray($vector);
			self::assertIsString($vector['jws']);
			$raw = self::decode(explode('.', $vector['jws'])[2]);
			$signatures[] = $raw;
			$r = ord($raw[0]);
			$s = ord($raw[48]);
			if($name === 'highBit'){
				self::assertTrue($r >= 128 || $s >= 128);
				self::assertTrue($r !== 0 && $s !== 0);
			}else{
				self::assertTrue($r === 0 || $s === 0);
				self::assertTrue($r < 128 && $s < 128);
			}
			self::assertSame($raw, $convert->invoke(null, self::der($raw)));
		}
		self::assertNotSame($signatures[0], $signatures[1]);
	}

	/** @return iterable<string, array{string}> */
	public static function malformedDer() : iterable{
		foreach(['', "\x30\x06\x02\x01\x00\x02\x01\x01", "\x30\x06\x02\x01\x80\x02\x01\x01", "\x30\x07\x02\x02\x00\x01\x02\x01\x01", "\x30\x06\x02\x01\x01\x02\x01\x01\x00", "\x30\x81\x06\x02\x01\x01\x02\x01\x01", "\x30\x06\x03\x01\x01\x02\x01\x01", "\x30\x06\x02\x05\x01\x02\x01\x01", "\x30\x36\x02\x31" . str_repeat("\x01", 49) . "\x02\x01\x01"] as $index => $der){
			yield 'DER ' . $index => [$der];
		}
	}

	#[DataProvider('malformedDer')]
	public function testMalformedDerFailsClosed(string $der) : void{
		$convert = new \ReflectionMethod(ServerIdentity::class, 'joseSignature');
		$this->expectException(TransportException::class);
		$convert->invoke(null, $der);
	}

	public function testRecursiveClaimsFailWithAnArgumentError() : void{
		$claims = [];
		$claims['cycle'] = &$claims;
		$this->expectException(\InvalidArgumentException::class);
		new ServerIdentity(self::$key, 'operator.test', 60, $claims);
	}

	public function testCustomJsonDataIsSignedWithoutInjectingJoseHeaders() : void{
		$signer = new ServerIdentity(self::$key, 'operator.test', 60, ['alg' => 'none', 'x5u' => 'https://untrusted.test/key', 'custom' => ['name' => 'é/host', 'enabled' => true, 'numbers' => [1, 1.5, null]]]);
		[$token] = self::assertion($signer->signServer(self::PAYLOAD, 1000));
		$claimsText = self::decode(explode('.', $token)[1]);
		self::assertStringContainsString('é/host', $claimsText);
		self::assertSame(1, self::verify($token, $claimsText, self::$key));
	}

	public function testSeparateFingerprintPayloadsCannotShareTheirSignatures() : void{
		$signer = new ServerIdentity(self::$key, 'operator.test');
		$other = str_replace('AA', 'aa', self::PAYLOAD);
		[, $first] = self::assertion($signer->signServer(self::PAYLOAD, 1000));
		[, $second] = self::assertion($signer->signServer($other, 1000));
		self::assertSame(1, self::verify($first, self::PAYLOAD, self::$key));
		self::assertSame(1, self::verify($second, $other, self::$key));
		self::assertSame(0, self::verify($first, $other, self::$key));
		self::assertSame(0, self::verify($second, self::PAYLOAD, self::$key));
	}

	public function testClaimReferencesCannotMutateAnExistingSigner() : void{
		$subject = 'original';
		$claims = ['sub' => &$subject];
		$signer = new ServerIdentity(self::$key, 'operator.test', 60, $claims);
		$subject = 'changed';
		[$token] = self::assertion($signer->signServer(self::PAYLOAD, 1000));
		$decoded = json_decode(self::decode(explode('.', $token)[1]), true, 16, JSON_THROW_ON_ERROR);
		self::assertIsArray($decoded);
		self::assertSame('original', $decoded['sub']);
	}

	public function testSelfAndMaximumLengthDnsDomainAreAccepted() : void{
		foreach(['self', str_repeat('a', 63) . '.' . str_repeat('b', 63) . '.' . str_repeat('c', 63) . '.' . str_repeat('d', 61)] as $domain){
			$signer = new ServerIdentity(self::$key, $domain);
			$value = $signer->signServer(self::PAYLOAD, 1000);
			$parsed = SdpIdentity::fromSdp("v=0\r\na=identity:" . $value . "\r\na=fingerprint:sha-256 " . self::DIGEST . "\r\n", new TransportConfig());
			self::assertSame($domain, $parsed->providerDomain);
		}
	}

	public function testJwtIdStringsRemainSignedWithoutCoercion() : void{
		foreach(['token-123', '42', ''] as $jti){
			$signer = new ServerIdentity(self::$key, 'operator.test', 60, ['jti' => $jti]);
			[$token] = self::assertion($signer->signServer(self::PAYLOAD, 1000));
			$claimsText = self::decode(explode('.', $token)[1]);
			$claims = json_decode($claimsText, true, 16, JSON_THROW_ON_ERROR);
			self::assertIsArray($claims);
			self::assertSame($jti, $claims['jti']);
			self::assertSame(1, self::verify($token, $claimsText, self::$key));
		}
	}

	/** @return iterable<string, array{mixed}> */
	public static function invalidJwtIds() : iterable{
		foreach([42, 1.5, true, false, null, [], ['id']] as $index => $jti){
			yield 'jti ' . $index => [$jti];
		}
	}

	#[DataProvider('invalidJwtIds')]
	public function testRejectsNonStringJwtIds(mixed $jti) : void{
		$this->expectException(\InvalidArgumentException::class);
		new ServerIdentity(self::$key, 'operator.test', 60, ['jti' => $jti]);
	}

	public function testFinalSdpLimitIncludesTheInsertedIdentityAttribute() : void{
		$config = new TransportConfig();
		$base = "v=0\r\ns=-\r\nt=0 0\r\na=fingerprint:sha-256 " . self::DIGEST . "\r\n";
		$media = "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
		$sdp = $base . 'a=x-padding:' . str_repeat('x', 65082 - strlen($base . $media) - 14) . "\r\n" . $media;
		self::assertSame(65082, strlen($sdp));
		$parsed = SdpIdentity::fromSdp($sdp, $config);
		$signer = new ServerIdentity(self::$key, 'operator.test');
		$value = $signer->signServer($parsed->canonicalFingerprints, 1000);
		$line = 'a=identity:' . $value . "\r\n";
		$offset = strpos($sdp, 'm=');
		self::assertNotFalse($offset);
		$answer = substr($sdp, 0, $offset) . $line . substr($sdp, $offset);
		self::assertSame(strlen($sdp) + strlen($line), strlen($answer));
		self::assertGreaterThan($config->maxSdpBytes, strlen($answer));
		$remaining = $config->maxSdpBytes - strlen($line);
		$atLimit = $base . 'a=x-padding:' . str_repeat('x', $remaining - strlen($base . $media) - 14) . "\r\n" . $line . $media;
		self::assertSame($config->maxSdpBytes, strlen($atLimit));
		$accepted = SdpIdentity::fromSdp($atLimit, $config);
		self::assertSame($parsed->canonicalFingerprints, $accepted->canonicalFingerprints);
		self::assertNotNull($accepted->detachedJws);
		self::assertSame(1, self::verify($accepted->detachedJws, $accepted->canonicalFingerprints, self::$key));
		foreach([$answer, str_replace('a=x-padding:', 'a=x-padding:x', $atLimit)] as $oversized){
			try{
				SdpIdentity::fromSdp($oversized, $config);
				self::fail('Oversized final SDP accepted');
			}catch(TransportException $e){
				self::assertSame('invalid_sdp', $e->errorCode);
			}
		}
	}
}
