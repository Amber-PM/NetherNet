<?php

declare(strict_types=1);

namespace amber\nethernet\tests\identity;

use amber\nethernet\TransportConfig;
use amber\nethernet\TransportException;
use amber\nethernet\identity\ClientIdentityVerifier;
use amber\nethernet\identity\IdentityHandler;
use amber\nethernet\identity\PeerIdentity;
use amber\nethernet\identity\SdpIdentity;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ClientIdentityVerifierTest extends TestCase{
	private static \OpenSSLAsymmetricKey $issuer;
	private static \OpenSSLAsymmetricKey $otherIssuer;
	private static \OpenSSLAsymmetricKey $client;
	private static \OpenSSLAsymmetricKey $otherClient;
	private const FINGERPRINT = 'a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99';
	private const PAYLOAD = '{"fingerprint":[{"algorithm":"sha-256","digest":"AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"}]}';

	public static function setUpBeforeClass() : void{
		self::$issuer = self::generateKey(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
		self::$otherIssuer = self::generateKey(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
		self::$client = self::generateKey(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']);
		self::$otherClient = self::generateKey(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']);
	}

	/** @param array<string, int|string> $options */
	private static function generateKey(array $options) : \OpenSSLAsymmetricKey{
		$key = openssl_pkey_new($options + ['config' => __DIR__ . '/openssl.cnf']);
		self::assertNotFalse($key);
		return $key;
	}

	private static function publicKey(\OpenSSLAsymmetricKey $key) : \OpenSSLAsymmetricKey{
		$details = openssl_pkey_get_details($key);
		self::assertNotFalse($details);
		$public = openssl_pkey_get_public($details['key']);
		self::assertNotFalse($public);
		return $public;
	}

	private static function der(\OpenSSLAsymmetricKey $key) : string{
		$details = openssl_pkey_get_details($key);
		self::assertNotFalse($details);
		$pem = preg_replace('/-----[^-]+-----|\s/', '', $details['key']);
		self::assertNotNull($pem);
		$der = base64_decode($pem, true);
		self::assertNotFalse($der);
		return $der;
	}

	/** @return array{kty: string, crv: string, x: string, y: string} */
	private static function jwk() : array{
		$details = openssl_pkey_get_details(self::$client);
		self::assertNotFalse($details);
		return ['kty' => 'EC', 'crv' => 'P-384', 'x' => self::url(str_pad($details['ec']['x'], 48, "\0", STR_PAD_LEFT)), 'y' => self::url(str_pad($details['ec']['y'], 48, "\0", STR_PAD_LEFT))];
	}

	private static function url(string $bytes) : string{
		return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
	}

	/** @return array<string, mixed> */
	private static function claims() : array{
		return ['iss' => 'https://issuer.test/', 'aud' => 'nethernet-test', 'sub' => 'player-123', 'exp' => 1100, 'nbf' => 900, 'iat' => 900, 'cpk' => self::jwk(), 'xid' => '1234567890123456'];
	}

	/**
	 * @param array<string, mixed> $header
	 * @param array<string, mixed> $claims
	 */
	private static function token(array $claims, array $header = ['alg' => 'RS256', 'kid' => 'trusted'], ?\OpenSSLAsymmetricKey $key = null) : string{
		$input = self::url(json_encode($header, JSON_THROW_ON_ERROR)) . '.' . self::url(json_encode($claims, JSON_THROW_ON_ERROR));
		self::assertTrue(openssl_sign($input, $signature, $key ?? self::$issuer, OPENSSL_ALGO_SHA256));
		return $input . '.' . self::url($signature);
	}

	/** @param array<string, mixed> $header */
	private static function detached(string $payload = self::PAYLOAD, array $header = ['alg' => 'ES384'], ?\OpenSSLAsymmetricKey $key = null) : string{
		$encodedHeader = self::url(json_encode($header, JSON_THROW_ON_ERROR));
		self::assertTrue(openssl_sign($encodedHeader . '.' . self::url($payload), $signature, $key ?? self::$client, OPENSSL_ALGO_SHA384));
		self::assertSame(0x30, ord($signature[0]));
		self::assertSame(0x02, ord($signature[2]));
		$rLength = ord($signature[3]);
		$r = substr($signature, 4, $rLength);
		$sOffset = 4 + $rLength;
		self::assertSame(0x02, ord($signature[$sOffset]));
		$s = substr($signature, $sOffset + 2, ord($signature[$sOffset + 1]));
		$raw = str_pad(ltrim($r, "\0"), 48, "\0", STR_PAD_LEFT) . str_pad(ltrim($s, "\0"), 48, "\0", STR_PAD_LEFT);
		self::assertSame(96, strlen($raw));
		return $encodedHeader . '..' . self::url($raw);
	}

	private static function identity(string $token, ?string $jws = null, string $fingerprints = self::FINGERPRINT, string $domain = 'untrusted.example') : SdpIdentity{
		$assertion = json_encode(['token' => $token, 'fingerprints' => $jws ?? self::detached()], JSON_THROW_ON_ERROR);
		$envelope = base64_encode(json_encode(['idp' => ['domain' => $domain, 'protocol' => 'default'], 'assertion' => $assertion], JSON_THROW_ON_ERROR));
		return SdpIdentity::fromSdp("v=0\r\n$fingerprints\r\na=identity:$envelope\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n", new TransportConfig());
	}

	private static function verifier() : ClientIdentityVerifier{
		return new ClientIdentityVerifier(fn(?string $kid) => $kid === 'trusted' || $kid === null ? self::publicKey(self::$issuer) : null, 'https://issuer.test/', 'nethernet-test');
	}

	public function testAuthenticatesRealRs256TokenAndEs384Fingerprints() : void{
		$peer = self::verifier()->verify(self::identity(self::token(self::claims())), 1000);
		self::assertSame('player-123', $peer->subject);
		self::assertSame(self::der(self::$client), $peer->publicKeyDer);
		self::assertSame('1234567890123456', $peer->claims['xid']);
	}

	public function testSpkiAndJwkAuthenticateTheSameClientKey() : void{
		$claims = self::claims();
		$claims['cpk'] = base64_encode(self::der(self::$client));
		$peer = self::verifier()->verify(self::identity(self::token($claims)), 1000);
		self::assertSame(self::der(self::$client), $peer->publicKeyDer);
	}

	public function testAudienceArrayAndMissingKidUseExplicitTrustPolicy() : void{
		$claims = self::claims();
		$claims['aud'] = ['another-service', 'nethernet-test'];
		$peer = self::verifier()->verify(self::identity(self::token($claims, ['alg' => 'RS256'])), 1000);
		self::assertSame('player-123', $peer->subject);
	}

	/** @return iterable<string, array{string, mixed}> */
	public static function invalidClaims() : iterable{
		yield 'wrong issuer' => ['iss', 'https://attacker.test/'];
		yield 'missing issuer' => ['iss', null];
		yield 'wrong audience' => ['aud', 'another-service'];
		yield 'mixed audience types' => ['aud', ['nethernet-test', 42]];
		yield 'empty audience' => ['aud', []];
		yield 'null audience' => ['aud', null];
		yield 'numeric subject' => ['sub', 42];
		yield 'empty subject' => ['sub', ''];
		yield 'missing subject' => ['sub', null];
		yield 'expired at boundary' => ['exp', 1000];
		yield 'expired' => ['exp', 999];
		yield 'string expiry' => ['exp', '1100'];
		yield 'missing expiry' => ['exp', null];
		yield 'not yet valid' => ['nbf', 1001];
		yield 'string nbf' => ['nbf', '900'];
		yield 'string issued-at' => ['iat', '900'];
		yield 'missing cpk' => ['cpk', null];
		yield 'numeric cpk' => ['cpk', 42];
		yield 'invalid base64 cpk' => ['cpk', '***'];
		yield 'not spki' => ['cpk', base64_encode('not a key')];
		yield 'wrong JWK curve' => ['cpk', ['kty' => 'EC', 'crv' => 'P-256', 'x' => 'AA', 'y' => 'AA']];
		yield 'RSA JWK' => ['cpk', ['kty' => 'RSA', 'n' => 'AA', 'e' => 'AQAB']];
		yield 'JWK missing coordinates' => ['cpk', ['kty' => 'EC', 'crv' => 'P-384']];
		yield 'JWK invalid point' => ['cpk', ['kty' => 'EC', 'crv' => 'P-384', 'x' => str_repeat('A', 64), 'y' => str_repeat('A', 64)]];
	}

	#[DataProvider('invalidClaims')]
	public function testRejectsInvalidClaimsAndKeys(string $claim, mixed $value) : void{
		$claims = self::claims();
		if($value === null){ unset($claims[$claim]); }else{ $claims[$claim] = $value; }
		$identity = self::identity(self::token($claims));
		$this->expectException(TransportException::class);
		self::verifier()->verify($identity, 1000);
	}

	/** @return iterable<string, array{array<string, mixed>}> */
	public static function invalidTokenHeaders() : iterable{
		yield 'none' => [['alg' => 'none']];
		yield 'HMAC confusion' => [['alg' => 'HS256']];
		yield 'ES384 is not a client token algorithm' => [['alg' => 'ES384']];
		yield 'missing alg' => [['typ' => 'JWT']];
		yield 'non-string alg' => [['alg' => 256]];
		yield 'non-string kid' => [['alg' => 'RS256', 'kid' => 1]];
		yield 'empty kid' => [['alg' => 'RS256', 'kid' => '']];
		yield 'unsupported critical extension' => [['alg' => 'RS256', 'crit' => ['custom'], 'custom' => true]];
		yield 'empty crit' => [['alg' => 'RS256', 'crit' => []]];
		yield 'unencoded payload' => [['alg' => 'RS256', 'b64' => false]];
	}

	/** @param array<string, mixed> $header */
	#[DataProvider('invalidTokenHeaders')]
	public function testRejectsUnexpectedTokenAlgorithmsAndHeaders(array $header) : void{
		$identity = self::identity(self::token(self::claims(), $header));
		$this->expectException(TransportException::class);
		self::verifier()->verify($identity, 1000);
	}

	/** @return iterable<string, array{array<string, mixed>}> */
	public static function invalidDetachedHeaders() : iterable{
		yield 'wrong alg' => [['alg' => 'RS256']];
		yield 'missing alg' => [['typ' => 'JWT']];
		yield 'HMAC' => [['alg' => 'HS384']];
		yield 'critical extension' => [['alg' => 'ES384', 'crit' => ['custom'], 'custom' => true]];
		yield 'b64 false' => [['alg' => 'ES384', 'b64' => false]];
	}

	/** @param array<string, mixed> $header */
	#[DataProvider('invalidDetachedHeaders')]
	public function testRejectsUnexpectedDetachedHeaders(array $header) : void{
		$identity = self::identity(self::token(self::claims()), self::detached(header: $header));
		$this->expectException(TransportException::class);
		self::verifier()->verify($identity, 1000);
	}

	public function testRejectsTokenSignedByAnUntrustedIssuer() : void{
		$identity = self::identity(self::token(self::claims(), key: self::$otherIssuer));
		$this->expectException(TransportException::class);
		self::verifier()->verify($identity, 1000);
	}

	public function testRejectsUnknownKidWithoutConsultingTokenUrls() : void{
		$identity = self::identity(self::token(self::claims(), ['alg' => 'RS256', 'kid' => 'unknown', 'jku' => 'https://attacker.test/keys', 'x5u' => 'file:///secret', 'jwk' => self::jwk()]));
		$this->expectException(TransportException::class);
		self::verifier()->verify($identity, 1000);
	}

	public function testRejectsAnAlteredTokenPayload() : void{
		$parts = explode('.', self::token(self::claims()));
		$claims = self::claims();
		$claims['sub'] = 'attacker';
		$parts[1] = self::url(json_encode($claims, JSON_THROW_ON_ERROR));
		$identity = self::identity(implode('.', $parts));
		$this->expectException(TransportException::class);
		self::verifier()->verify($identity, 1000);
	}

	public function testRejectsFingerprintsSignedByAnotherClient() : void{
		$identity = self::identity(self::token(self::claims()), self::detached(key: self::$otherClient));
		$this->expectException(TransportException::class);
		self::verifier()->verify($identity, 1000);
	}

	public function testRejectsFingerprintsChangedAfterSigning() : void{
		$identity = self::identity(self::token(self::claims()), fingerprints: str_replace('AA:BB', 'AB:BB', self::FINGERPRINT));
		$this->expectException(TransportException::class);
		self::verifier()->verify($identity, 1000);
	}

	/** @return iterable<string, array{int}> */
	public static function invalidSignatureLengths() : iterable{
		yield 'truncated' => [95];
		yield 'extra octet' => [97];
		yield 'zero scalars' => [96];
	}

	#[DataProvider('invalidSignatureLengths')]
	public function testRejectsMalformedEs384Signatures(int $length) : void{
		$jws = self::url('{"alg":"ES384"}') . '..' . self::url(str_repeat("\0", $length));
		$identity = self::identity(self::token(self::claims()), $jws);
		$this->expectException(TransportException::class);
		self::verifier()->verify($identity, 1000);
	}

	public function testRejectsMissingIdentity() : void{
		$identity = SdpIdentity::fromSdp('v=0' . "\n" . self::FINGERPRINT . "\n", new TransportConfig());
		$this->expectException(TransportException::class);
		self::verifier()->verify($identity, 1000);
	}

	public function testClockSkewHasExactExpiryAndNotBeforeBoundaries() : void{
		$verifier = new ClientIdentityVerifier(fn(?string $kid) => self::publicKey(self::$issuer), 'https://issuer.test/', 'nethernet-test', clockSkewSeconds: 5);
		$claims = self::claims();
		$claims['nbf'] = 1005;
		$claims['exp'] = 996;
		self::assertSame('player-123', $verifier->verify(self::identity(self::token($claims)), 1000)->subject);
		$claims['exp'] = 995;
		$identity = self::identity(self::token($claims));
		$this->expectException(TransportException::class);
		$verifier->verify($identity, 1000);
	}

	public function testFractionalNumericDatesAreNotTruncated() : void{
		$claims = self::claims();
		$claims['exp'] = 1000.5;
		$claims['nbf'] = 999.5;
		$claims['iat'] = 1001.25;
		self::assertSame('player-123', self::verifier()->verify(self::identity(self::token($claims)), 1000)->subject);
	}

	public function testExpiryPresenceAndSubjectMappingAreExplicitPolicy() : void{
		$claims = self::claims();
		unset($claims['exp'], $claims['sub']);
		$verifier = new ClientIdentityVerifier(fn(?string $kid) => self::publicKey(self::$issuer), 'https://issuer.test/', 'nethernet-test', requireExpiry: false, subjectClaim: 'xid');
		self::assertSame('1234567890123456', $verifier->verify(self::identity(self::token($claims)), 1000)->subject);
	}

	public function testMultipleFingerprintScopesPreserveOrderCaseAndLineEndings() : void{
		$second = strtolower(self::FINGERPRINT);
		$fingerprints = self::FINGERPRINT . "\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" . $second;
		$payload = substr(self::PAYLOAD, 0, -2) . ',' . strtolower(substr(self::PAYLOAD, strlen('{"fingerprint":['), -2)) . ']}';
		$token = self::token(self::claims());
		$jws = self::detached($payload);
		$assertion = json_encode(['token' => $token, 'fingerprints' => $jws], JSON_THROW_ON_ERROR);
		$envelope = base64_encode(json_encode(['idp' => ['domain' => 'untrusted.example', 'protocol' => 'default'], 'assertion' => $assertion], JSON_THROW_ON_ERROR));
		$sdp = "v=0\r\na=identity:$envelope\r\n$fingerprints\r\n";
		foreach([$sdp, str_replace("\r\n", "\n", $sdp)] as $offer){
			self::assertSame('player-123', self::verifier()->verify(SdpIdentity::fromSdp($offer, new TransportConfig()), 1000)->subject);
		}
		$identity = SdpIdentity::fromSdp(str_replace('AA:BB', 'aa:bb', $sdp), new TransportConfig());
		$this->expectException(TransportException::class);
		self::verifier()->verify($identity, 1000);
	}

	public function testResolverFailuresAreReportedWithoutFallback() : void{
		$failure = new \RuntimeException('key store unavailable');
		$verifier = new ClientIdentityVerifier(fn(?string $kid) => throw $failure, 'https://issuer.test/', 'nethernet-test');
		try{
			$verifier->verify(self::identity(self::token(self::claims())), 1000);
			self::fail('Key resolution failure was accepted');
		}catch(TransportException $e){
			self::assertSame('identity_trust_failed', $e->errorCode);
			self::assertSame($failure, $e->getPrevious());
		}
	}

	public function testEcKeyCannotBeUsedAsAnRs256TrustAnchor() : void{
		$verifier = new ClientIdentityVerifier(fn(?string $kid) => self::publicKey(self::$client), 'https://issuer.test/', 'nethernet-test');
		$identity = self::identity(self::token(self::claims()));
		$this->expectException(TransportException::class);
		$verifier->verify($identity, 1000);
	}

	public function testWeakRsaTrustKeysAreRejected() : void{
		$key = self::generateKey(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 1024]);
		$identity = self::identity(self::token(self::claims(), key: $key));
		$verifier = new ClientIdentityVerifier(fn(?string $kid) => self::publicKey($key), 'https://issuer.test/', 'nethernet-test');
		$this->expectException(TransportException::class);
		$verifier->verify($identity, 1000);
	}

	/** @return iterable<string, array{string}> */
	public static function malformedRsaSignatures() : iterable{
		yield 'truncated RSA signature' => [str_repeat("\0", 255)];
		yield 'oversize RSA signature' => [str_repeat("\0", 257)];
		yield 'invalid RSA signature' => [str_repeat("\0", 256)];
	}

	#[DataProvider('malformedRsaSignatures')]
	public function testRejectsInvalidRsaSignatures(string $signature) : void{
		$parts = explode('.', self::token(self::claims()));
		$parts[2] = self::url($signature);
		$identity = self::identity(implode('.', $parts));
		$this->expectException(TransportException::class);
		self::verifier()->verify($identity, 1000);
	}

	/** @return iterable<string, array{string, mixed}> */
	public static function malformedJwkFields() : iterable{
		yield 'short x' => ['x', 'AA'];
		yield 'padded coordinate' => ['x', str_repeat('A', 64) . '='];
		yield 'invalid base64url' => ['x', '***'];
		yield 'wrong metadata algorithm' => ['alg', 'ES256'];
		yield 'encryption key' => ['use', 'enc'];
		yield 'private key claim' => ['d', 'AA'];
		yield 'wrong operations' => ['key_ops', ['encrypt']];
		yield 'non-string operation' => ['key_ops', ['verify', 1]];
	}

	#[DataProvider('malformedJwkFields')]
	public function testRejectsMalformedJwkEncodingAndMetadata(string $field, mixed $value) : void{
		$claims = self::claims();
		$jwk = self::jwk();
		$jwk[$field] = $value;
		$claims['cpk'] = $jwk;
		$identity = self::identity(self::token($claims));
		$this->expectException(TransportException::class);
		self::verifier()->verify($identity, 1000);
	}

	public function testRejectsTrailingSpkiBytes() : void{
		$claims = self::claims();
		$claims['cpk'] = base64_encode(self::der(self::$client) . "\0");
		$identity = self::identity(self::token($claims));
		$this->expectException(TransportException::class);
		self::verifier()->verify($identity, 1000);
	}

	public function testRejectsRsaAndP256ClientSpki() : void{
		$p256 = self::generateKey(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
		foreach([self::$issuer, $p256] as $key){
			$claims = self::claims();
			$claims['cpk'] = base64_encode(self::der($key));
			try{
				self::verifier()->verify(self::identity(self::token($claims)), 1000);
				self::fail('Client key on the wrong algorithm was accepted');
			}catch(TransportException $e){
				self::assertSame('identity_key_invalid', $e->errorCode);
			}
		}
	}

	public function testPresentNullDatesAreInvalidEvenWhenExpiryIsOptional() : void{
		$verifier = new ClientIdentityVerifier(fn(?string $kid) => self::publicKey(self::$issuer), 'https://issuer.test/', 'nethernet-test', requireExpiry: false);
		foreach(['exp', 'nbf', 'iat'] as $name){
			$claims = self::claims();
			$claims[$name] = null;
			try{
				$verifier->verify(self::identity(self::token($claims)), 1000);
				self::fail('Null NumericDate was accepted');
			}catch(TransportException $e){
				self::assertSame('identity_claims_invalid', $e->errorCode);
			}
		}
	}

	/** @return iterable<string, array{string}> */
	public static function malformedCompactTokens() : iterable{
		yield 'truncated token' => ['e30.e30'];
		yield 'extra segment' => ['e30.e30.AA.AA'];
		yield 'empty signature' => ['e30.e30.'];
		yield 'padded header' => ['e30=.e30.AA'];
		yield 'noncanonical bits' => ['e31.e30.AA'];
		yield 'duplicate algorithm' => [rtrim(strtr(base64_encode('{"alg":"RS256","alg":"none"}'), '+/', '-_'), '=') . '.e30.AA'];
		yield 'duplicate claim' => ['e30.' . rtrim(strtr(base64_encode('{"exp":1100,"exp":999}'), '+/', '-_'), '=') . '.AA'];
		yield 'array claims' => ['e30.W10.AA'];
	}

	#[DataProvider('malformedCompactTokens')]
	public function testMalformedCompactInputNeverProducesAnIdentity(string $token) : void{
		$this->expectException(TransportException::class);
		self::verifier()->verify(self::identity($token), 1000);
	}

	public function testDetachedPayloadCannotBeIncluded() : void{
		$jws = self::url('{"alg":"ES384"}') . '.' . self::url(self::PAYLOAD) . '.AA';
		$this->expectException(TransportException::class);
		self::verifier()->verify(self::identity(self::token(self::claims()), $jws), 1000);
	}

	public function testCanonicalFingerprintBytesCannotBeReplacedWithEquivalentJson() : void{
		$identity = self::identity(self::token(self::claims()), self::detached(str_replace(':', ': ', self::PAYLOAD)));
		$this->expectException(TransportException::class);
		self::verifier()->verify($identity, 1000);
	}

	public function testOptionalDatesAndNoncriticalHeadersDoNotBreakValidTokens() : void{
		$claims = self::claims();
		unset($claims['nbf'], $claims['iat']);
		$jwk = self::jwk() + ['alg' => 'ES384', 'use' => 'sig', 'key_ops' => ['verify']];
		$claims['cpk'] = $jwk;
		$token = self::token($claims, ['kid' => 'trusted', 'typ' => 'JWT', 'alg' => 'RS256', 'b64' => true, 'jku' => 'https://untrusted.example/keys']);
		self::assertSame('player-123', self::verifier()->verify(self::identity($token, self::detached(header: ['typ' => 'JWT', 'alg' => 'ES384', 'b64' => true])), 1000)->subject);
	}

	public function testInvalidPolicyConfigurationIsRejected() : void{
		$this->expectException(\InvalidArgumentException::class);
		new ClientIdentityVerifier(fn(?string $kid) => self::publicKey(self::$issuer), '', 'nethernet-test');
	}

	public function testNegativeVerificationTimeIsRejected() : void{
		$identity = self::identity(self::token(self::claims()));
		$this->expectException(\InvalidArgumentException::class);
		self::verifier()->verify($identity, -1);
	}

	public function testIndependentP1363VectorsCoverLeadingZeroAndHighBitIntegers() : void{
		$json = file_get_contents(__DIR__ . '/fixtures/es384.json');
		self::assertNotFalse($json);
		$fixture = json_decode($json, true, 16, JSON_THROW_ON_ERROR);
		self::assertIsArray($fixture);
		self::assertIsArray($fixture['vectors']);
		self::assertIsArray($fixture['vectors']['leadingZero']);
		self::assertIsArray($fixture['vectors']['highBit']);
		self::assertNotSame($fixture['vectors']['leadingZero']['jws'], $fixture['vectors']['highBit']['jws']);
		self::assertNotSame($fixture['vectors']['leadingZero']['publicKeyDer'], $fixture['vectors']['highBit']['publicKeyDer']);
		$claims = self::claims();
		foreach($fixture['vectors'] as $name => $vector){
			self::assertIsArray($vector);
			self::assertSame(self::PAYLOAD, $vector['payload']);
			self::assertIsString($vector['publicKeyDer']);
			$der = base64_decode($vector['publicKeyDer'], true);
			self::assertNotFalse($der);
			foreach([$vector['cpk'], $vector['publicKeyDer']] as $cpk){
				$claims['cpk'] = $cpk;
				$jws = $vector['jws'];
				self::assertIsString($jws);
				$parts = explode('.', $jws);
				$raw = base64_decode(strtr($parts[2], '-_', '+/'), true);
				self::assertNotFalse($raw);
				self::assertSame(96, strlen($raw));
				if($name === 'leadingZero'){
					self::assertTrue($raw[0] === "\0" || $raw[48] === "\0");
					self::assertSame(0, (ord($raw[0]) | ord($raw[48])) & 0x80);
				}else{
					self::assertTrue((ord($raw[0]) & 0x80) !== 0 || (ord($raw[48]) & 0x80) !== 0);
					self::assertNotSame("\0", $raw[0]);
					self::assertNotSame("\0", $raw[48]);
				}
				self::assertSame($der, self::verifier()->verify(self::identity(self::token($claims), $jws), 1000)->publicKeyDer);
			}
		}
	}

	public function testNonfiniteNumericDatesWithValidSignaturesAreRejected() : void{
		foreach(['exp', 'nbf', 'iat'] as $name){
			$claims = self::claims();
			$claims[$name] = 12345;
			$json = str_replace('"' . $name . '":12345', '"' . $name . '":1e999', json_encode($claims, JSON_THROW_ON_ERROR));
			$input = self::url('{"alg":"RS256","kid":"trusted"}') . '.' . self::url($json);
			self::assertTrue(openssl_sign($input, $signature, self::$issuer, OPENSSL_ALGO_SHA256));
			try{
				self::verifier()->verify(self::identity($input . '.' . self::url($signature)), 1000);
				self::fail('Nonfinite NumericDate was accepted');
			}catch(TransportException $e){
				self::assertSame('identity_claims_invalid', $e->errorCode);
			}
		}
	}

	public function testMissingKidTriesEveryTrustedCandidateWithoutRequiringIssuerPreselection() : void{
		$identity = self::identity(self::token(self::claims(), ['alg' => 'RS256'], self::$otherIssuer));
		$verifier = new ClientIdentityVerifier(fn(?string $kid) => [self::publicKey(self::$issuer), self::publicKey(self::$otherIssuer)], 'https://issuer.test/', 'nethernet-test');
		self::assertSame('player-123', $verifier->verify($identity, 1000)->subject);
	}

	public function testTrustedKeyRotationUpdatesTheSameVerifier() : void{
		$keys = [self::publicKey(self::$issuer)];
		$verifier = new ClientIdentityVerifier(static function(?string $kid) use (&$keys){ return $keys; }, 'https://issuer.test/', 'nethernet-test');
		$old = self::identity(self::token(self::claims(), ['alg' => 'RS256']));
		$new = self::identity(self::token(self::claims(), ['alg' => 'RS256'], self::$otherIssuer));
		self::assertSame('player-123', $verifier->verify($old, 1000)->subject);
		$keys[] = self::publicKey(self::$otherIssuer);
		self::assertSame('player-123', $verifier->verify($new, 1000)->subject);
		$keys = [self::publicKey(self::$otherIssuer)];
		self::assertSame('player-123', $verifier->verify($new, 1000)->subject);
		$this->expectException(TransportException::class);
		$verifier->verify($old, 1000);
	}

	public function testNoTrustedCandidateMayValidateAnInvalidSignature() : void{
		$parts = explode('.', self::token(self::claims()));
		$parts[2] = self::url(str_repeat("\0", 256));
		$identity = self::identity(implode('.', $parts));
		$verifier = new ClientIdentityVerifier(fn(?string $kid) => [self::publicKey(self::$issuer), self::publicKey(self::$otherIssuer)], 'https://issuer.test/', 'nethernet-test');
		$this->expectException(TransportException::class);
		$verifier->verify($identity, 1000);
	}

	public function testKnownKidIsPassedToPolicyWithoutFallingBackToAnotherTrustSet() : void{
		$identity = self::identity(self::token(self::claims(), ['alg' => 'RS256', 'kid' => 'new'], self::$otherIssuer));
		$verifier = new ClientIdentityVerifier(fn(?string $kid) => $kid === 'new' ? [self::publicKey(self::$otherIssuer)] : [], 'https://issuer.test/', 'nethernet-test');
		self::assertSame('player-123', $verifier->verify($identity, 1000)->subject);
		$unknown = self::identity(self::token(self::claims(), ['alg' => 'RS256', 'kid' => 'unknown'], self::$otherIssuer));
		$this->expectException(TransportException::class);
		$verifier->verify($unknown, 1000);
	}

	public function testCandidateLimitRejectsTheWholeBatchEvenIfTheFirstKeyMatches() : void{
		$identity = self::identity(self::token(self::claims()));
		$key = self::publicKey(self::$issuer);
		$verifier = new ClientIdentityVerifier(fn(?string $kid) => array_fill(0, 9, $key), 'https://issuer.test/', 'nethernet-test');
		try{
			$verifier->verify($identity, 1000);
			self::fail('Oversize trusted key batch was accepted');
		}catch(TransportException $e){
			self::assertSame('identity_trust_limit', $e->errorCode);
		}
	}

	public function testExactlyTheConfiguredCandidateLimitCanAuthenticateTheLastKey() : void{
		$identity = self::identity(self::token(self::claims(), key: self::$otherIssuer));
		$verifier = new ClientIdentityVerifier(fn(?string $kid) => [self::publicKey(self::$issuer), self::publicKey(self::$otherIssuer)], 'https://issuer.test/', 'nethernet-test', maxTrustedKeys: 2);
		self::assertSame('player-123', $verifier->verify($identity, 1000)->subject);
	}

	/** @return iterable<string, array{int}> */
	public static function invalidCandidateLimits() : iterable{
		yield 'zero' => [0];
		yield 'negative' => [-1];
		yield 'unbounded work configuration' => [33];
	}

	#[DataProvider('invalidCandidateLimits')]
	public function testCandidateLimitConfigurationIsBounded(int $limit) : void{
		$this->expectException(\InvalidArgumentException::class);
		new ClientIdentityVerifier(fn(?string $kid) => self::publicKey(self::$issuer), 'https://issuer.test/', 'nethernet-test', maxTrustedKeys: $limit);
	}

	public function testMalformedCandidateBatchesFailClosedBeforeAcceptingAnyKey() : void{
		$key = self::publicKey(self::$issuer);
		foreach([[], ['named' => $key], [$key, 'not a key'], [$key, self::publicKey(self::$client)]] as $batch){
			// deliberately invalid resolver output
			$verifier = (new \ReflectionClass(ClientIdentityVerifier::class))->newInstance(fn(?string $kid) => $batch, 'https://issuer.test/', 'nethernet-test');
			try{
				$verifier->verify(self::identity(self::token(self::claims())), 1000);
				self::fail('Invalid candidate batch was accepted');
			}catch(TransportException $e){
				self::assertSame('identity_untrusted', $e->errorCode);
			}
		}
	}

	public function testOverflowingClockPolicyFailsBeforeCryptographicWork() : void{
		$claims = self::claims();
		$claims['nbf'] = (float) PHP_INT_MAX + 2048.0;
		$identity = self::identity(self::token($claims));
		$lookups = 0;
		$verifier = new ClientIdentityVerifier(function(?string $kid) use (&$lookups) : \OpenSSLAsymmetricKey{
			++$lookups;
			return self::publicKey(self::$issuer);
		}, 'https://issuer.test/', 'nethernet-test', clockSkewSeconds: PHP_INT_MAX);
		try{
			$verifier->verify($identity, 2000);
			self::fail('Overflowing clock policy was accepted');
		}catch(\InvalidArgumentException){
			self::assertSame(0, $lookups);
		}
	}

	public function testExactClockArithmeticBoundaryPreservesNotBeforeSemantics() : void{
		$limit = min(PHP_INT_MAX, 9007199254740991);
		$claims = self::claims();
		$claims['exp'] = PHP_INT_MAX;
		$claims['nbf'] = $limit;
		$verifier = new ClientIdentityVerifier(fn(?string $kid) => self::publicKey(self::$issuer), 'https://issuer.test/', 'nethernet-test', clockSkewSeconds: 1);
		self::assertSame('player-123', $verifier->verify(self::identity(self::token($claims)), $limit - 1)->subject);
		$identity = self::identity(self::token($claims));
		$this->expectException(\InvalidArgumentException::class);
		$verifier->verify($identity, $limit);
	}

	public function testDifferentRsaKeySizesCanAuthenticateTheMatchingCandidate() : void{
		$large = self::generateKey(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 4096]);
		$verifier = new ClientIdentityVerifier(fn(?string $kid) => [self::publicKey($large), self::publicKey(self::$issuer)], 'https://issuer.test/', 'nethernet-test');
		self::assertSame('player-123', $verifier->verify(self::identity(self::token(self::claims())), 1000)->subject);
	}

	private static function offerHandler(SdpIdentity $offer, ClientIdentityVerifier $verifier) : IdentityHandler{
		return new class($offer, $verifier) implements IdentityHandler{
			public function __construct(private readonly SdpIdentity $offer, private readonly ClientIdentityVerifier $verifier){}

			/**
			 * @param \Closure(?PeerIdentity, ?TransportException): void $complete
			 * @return \Closure(): void
			 */
			public function verifyClient(string $token, string $canonicalFingerprints, string $detachedJws, \Closure $complete) : \Closure{
				$peer = null;
				$error = null;
				try{
					if($token !== $this->offer->token || $canonicalFingerprints !== $this->offer->canonicalFingerprints || $detachedJws !== $this->offer->detachedJws){
						throw new TransportException('identity_invalid', 'Handler arguments do not match the parsed offer');
					}
					$peer = $this->verifier->verify($this->offer, 1000);
				}catch(TransportException $failure){
					$error = $failure;
				}
				// don't catch the consumer callback
				$complete($peer, $error);
				return static function() : void{};
			}

			public function signServer(string $canonicalFingerprints, int $now) : string{
				throw new \LogicException('Server signing is outside this test adapter');
			}
		};
	}

	public function testIdentityHandlerCanComposeRealVerificationOnceAndCompleteOnce() : void{
		$offer = self::identity(self::token(self::claims()));
		self::assertNotNull($offer->token);
		self::assertNotNull($offer->detachedJws);
		$lookups = 0;
		$verifier = new ClientIdentityVerifier(function(?string $kid) use (&$lookups) : \OpenSSLAsymmetricKey{
			++$lookups;
			return self::publicKey(self::$issuer);
		}, 'https://issuer.test/', 'nethernet-test');
		$completed = 0;
		$handler = self::offerHandler($offer, $verifier);
		$cancel = $handler->verifyClient($offer->token, $offer->canonicalFingerprints, $offer->detachedJws, static function(?PeerIdentity $peer, ?TransportException $error) use (&$completed) : void{
			++$completed;
			self::assertNull($error);
			self::assertNotNull($peer);
			self::assertSame('player-123', $peer->subject);
		});
		$cancel();
		$cancel();
		self::assertSame(1, $lookups);
		self::assertSame(1, $completed);
	}

	/** @return iterable<string, array{int}> */
	public static function mismatchedHandlerArguments() : iterable{
		yield 'token' => [0];
		yield 'fingerprints' => [1];
		yield 'detached JWS' => [2];
	}

	#[DataProvider('mismatchedHandlerArguments')]
	public function testIdentityHandlerRejectsEveryArgumentMismatchBeforeCrypto(int $argument) : void{
		$offer = self::identity(self::token(self::claims()));
		self::assertNotNull($offer->token);
		self::assertNotNull($offer->detachedJws);
		$lookups = 0;
		$verifier = new ClientIdentityVerifier(function(?string $kid) use (&$lookups) : \OpenSSLAsymmetricKey{
			++$lookups;
			return self::publicKey(self::$issuer);
		}, 'https://issuer.test/', 'nethernet-test');
		$args = [$offer->token, $offer->canonicalFingerprints, $offer->detachedJws];
		$args[$argument] .= 'changed';
		$completed = 0;
		self::offerHandler($offer, $verifier)->verifyClient($args[0], $args[1], $args[2], static function(?PeerIdentity $peer, ?TransportException $error) use (&$completed) : void{
			++$completed;
			self::assertNull($peer);
			self::assertNotNull($error);
			self::assertSame('identity_invalid', $error->errorCode);
		});
		self::assertSame(0, $lookups);
		self::assertSame(1, $completed);
	}

	public function testIdentityHandlerCompletesWithErrorForAnInvalidRealSignature() : void{
		$offer = self::identity(self::token(self::claims()), self::detached(key: self::$otherClient));
		self::assertNotNull($offer->token);
		self::assertNotNull($offer->detachedJws);
		$completed = 0;
		self::offerHandler($offer, self::verifier())->verifyClient($offer->token, $offer->canonicalFingerprints, $offer->detachedJws, static function(?PeerIdentity $peer, ?TransportException $error) use (&$completed) : void{
			++$completed;
			self::assertNull($peer);
			self::assertNotNull($error);
			self::assertSame('identity_signature_invalid', $error->errorCode);
		});
		self::assertSame(1, $completed);
	}

	public function testConsumerCallbackErrorsCannotBecomeASecondCompletion() : void{
		$offer = self::identity(self::token(self::claims()));
		self::assertNotNull($offer->token);
		self::assertNotNull($offer->detachedJws);
		$completed = 0;
		$failure = new TransportException('consumer_error', 'consumer failed');
		try{
			self::offerHandler($offer, self::verifier())->verifyClient($offer->token, $offer->canonicalFingerprints, $offer->detachedJws, static function(?PeerIdentity $peer, ?TransportException $error) use (&$completed, $failure) : void{
				++$completed;
				throw $failure;
			});
			self::fail('Consumer exception was swallowed');
		}catch(TransportException $error){
			self::assertSame($failure, $error);
		}
		self::assertSame(1, $completed);
	}
}
