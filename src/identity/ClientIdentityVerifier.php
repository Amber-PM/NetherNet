<?php

declare(strict_types=1);

namespace amber\nethernet\identity;

use amber\nethernet\TransportException;

final class ClientIdentityVerifier{
	/**
	 * @param \Closure(?string): (\OpenSSLAsymmetricKey|list<\OpenSSLAsymmetricKey>|null) $trustedKey
	 * @throws \InvalidArgumentException
	 * @throws TransportException
	 */
	public function __construct(
		private readonly \Closure $trustedKey,
		private readonly string $expectedIssuer,
		private readonly string $expectedAudience,
		private readonly int $clockSkewSeconds = 0,
		private readonly bool $requireExpiry = true,
		private readonly string $subjectClaim = 'sub',
		private readonly int $maxTrustedKeys = 8
	){
		if($expectedIssuer === '' || $expectedAudience === '' || $subjectClaim === '' || $clockSkewSeconds < 0){
			throw new \InvalidArgumentException('Issuer, audience and subject claim must be nonempty; clock skew must be nonnegative');
		}
		if($maxTrustedKeys < 1 || $maxTrustedKeys > 32){
			throw new \InvalidArgumentException('Trusted key candidate limit must be between 1 and 32');
		}
		if(!extension_loaded('openssl')){
			throw new TransportException('crypto_unavailable', 'Client identity verification requires ext-openssl');
		}
	}

	/**
	 * @throws TransportException
	 * @throws \InvalidArgumentException
	 */
	public function verify(SdpIdentity $identity, int $now) : PeerIdentity{
		// overflow can admit a future nbf
		$clockLimit = min(PHP_INT_MAX, 9007199254740991);
		if($now < 0 || $this->clockSkewSeconds > $clockLimit || $now > $clockLimit - $this->clockSkewSeconds){
			throw new \InvalidArgumentException('Verification time and clock skew must fit exact integer clock arithmetic');
		}
		if($identity->token === null || $identity->detachedJws === null){
			throw new TransportException('identity_missing', 'Client identity assertion is required');
		}
		// parsed by SdpIdentity
		$token = explode('.', $identity->token);
		$header = self::object(self::decode($token[0]));
		self::checkHeader($header, 'RS256');
		$kid = $header->kid ?? null;
		if(property_exists($header, 'kid') && (!is_string($kid) || $kid === '')){
			throw new TransportException('identity_invalid', 'Token kid must be a nonempty string');
		}
		try{
			$resolved = ($this->trustedKey)($kid);
		}catch(\Throwable $e){
			throw new TransportException('identity_trust_failed', 'Trusted key resolution failed', $e);
		}
		$keys = $this->candidateKeys($resolved);
		$signature = self::decode($token[2]);
		$valid = false;
		foreach($keys as $key){
			$result = openssl_verify($token[0] . '.' . $token[1], $signature, $key, OPENSSL_ALGO_SHA256);
			if($result === 1){
				$valid = true;
				break;
			}
			if($result !== 0){
				throw new TransportException('identity_signature_invalid', 'OpenSSL failed to verify the client token');
			}
		}
		if(!$valid){
			throw new TransportException('identity_signature_invalid', 'No trusted key validates the client token');
		}
		$claims = get_object_vars(self::object(self::decode($token[1])));
		$subject = $this->checkClaims($claims, $now);
		[$clientKey, $der] = self::clientKey($claims['cpk'] ?? null);
		$jws = explode('.', $identity->detachedJws);
		self::checkHeader(self::object(self::decode($jws[0])), 'ES384');
		$signature = self::decode($jws[2]);
		if(strlen($signature) !== 96){
			throw new TransportException('identity_invalid', 'ES384 requires a 96-byte JOSE signature');
		}
		$r = self::derInteger(substr($signature, 0, 48));
		$s = self::derInteger(substr($signature, 48));
		$signatureDer = "\x30" . chr(strlen($r . $s)) . $r . $s;
		self::verifySignature($jws[0] . '.' . self::encode($identity->canonicalFingerprints), $signatureDer, $clientKey, OPENSSL_ALGO_SHA384);
		return new PeerIdentity($subject, $der, $claims);
	}

	/** @return non-empty-list<\OpenSSLAsymmetricKey> */
	private function candidateKeys(mixed $resolved) : array{
		$keys = $resolved instanceof \OpenSSLAsymmetricKey ? [$resolved] : $resolved;
		if(!is_array($keys) || $keys === []){
			throw new TransportException('identity_untrusted', 'No trusted key for the client token');
		}
		if(count($keys) > $this->maxTrustedKeys){
			throw new TransportException('identity_trust_limit', 'Trusted key candidate batch exceeds the configured limit');
		}
		if(!array_is_list($keys)){
			throw new TransportException('identity_untrusted', 'Trusted key candidates must be a list');
		}
		// check all keys before trying signatures
		foreach($keys as $key){
			if(!$key instanceof \OpenSSLAsymmetricKey){
				throw new TransportException('identity_untrusted', 'Invalid trusted key candidate');
			}
			$details = openssl_pkey_get_details($key);
			if($details === false || $details['type'] !== OPENSSL_KEYTYPE_RSA || $details['bits'] < 2048){
				throw new TransportException('identity_untrusted', 'RS256 requires trusted RSA keys of at least 2048 bits');
			}
		}
		return $keys;
	}

	private static function checkHeader(\stdClass $header, string $algorithm) : void{
		if(($header->alg ?? null) !== $algorithm || property_exists($header, 'crit') ||
			(property_exists($header, 'b64') && $header->b64 !== true)){
			throw new TransportException('identity_invalid', 'Unexpected JOSE algorithm or unsupported header extension');
		}
	}

	/** @param array<string, mixed> $claims */
	private function checkClaims(array $claims, int $now) : string{
		$audience = $claims['aud'] ?? null;
		$audiences = is_string($audience) ? [$audience] : $audience;
		if(!is_array($audiences) || !array_is_list($audiences) || $audiences === []){
			throw new TransportException('identity_claims_invalid', 'Token audience must be a string or nonempty string list');
		}
		foreach($audiences as $value){
			if(!is_string($value) || $value === ''){
				throw new TransportException('identity_claims_invalid', 'Token audience contains an invalid value');
			}
		}
		$subject = $claims[$this->subjectClaim] ?? null;
		if(($claims['iss'] ?? null) !== $this->expectedIssuer || !in_array($this->expectedAudience, $audiences, true) || !is_string($subject) || $subject === ''){
			throw new TransportException('identity_claims_invalid', 'Token issuer, audience or subject does not match the configured policy');
		}
		if($this->requireExpiry && !array_key_exists('exp', $claims)){
			throw new TransportException('identity_claims_invalid', 'Token expiry is required by the configured policy');
		}
		foreach(['exp', 'nbf', 'iat'] as $name){
			if(!array_key_exists($name, $claims)){
				continue;
			}
			$value = $claims[$name];
			if((!is_int($value) && !is_float($value)) || !is_finite((float) $value)){
				throw new TransportException('identity_claims_invalid', 'Token timestamps must be finite NumericDates');
			}
			if(($name === 'exp' && $now - $this->clockSkewSeconds >= $value) ||
				($name === 'nbf' && $now + $this->clockSkewSeconds < $value)){
				throw new TransportException('identity_expired', 'Token is expired or not yet valid');
			}
		}
		return $subject;
	}

	/** @return array{\OpenSSLAsymmetricKey, string} */
	private static function clientKey(mixed $cpk) : array{
		if($cpk instanceof \stdClass){
			if(($cpk->kty ?? null) !== 'EC' || ($cpk->crv ?? null) !== 'P-384' ||
				!is_string($cpk->x ?? null) || !is_string($cpk->y ?? null) || property_exists($cpk, 'd') ||
				(property_exists($cpk, 'alg') && $cpk->alg !== 'ES384') ||
				(property_exists($cpk, 'use') && $cpk->use !== 'sig')){
				throw new TransportException('identity_key_invalid', 'Client JWK must describe a public P-384 signature key');
			}
			if(property_exists($cpk, 'key_ops')){
				if(!is_array($cpk->key_ops) || !array_is_list($cpk->key_ops) || !in_array('verify', $cpk->key_ops, true)){
					throw new TransportException('identity_key_invalid', 'Client JWK does not permit verification');
				}
				foreach($cpk->key_ops as $operation){
					if(!is_string($operation)){
						throw new TransportException('identity_key_invalid', 'Invalid JWK key operations');
					}
				}
			}
			$x = self::decode($cpk->x);
			$y = self::decode($cpk->y);
			if(strlen($x) !== 48 || strlen($y) !== 48){
				throw new TransportException('identity_key_invalid', 'P-384 coordinates must be 48 bytes each');
			}
			// p-384 spki with an uncompressed point
			$der = hex2bin('3076301006072a8648ce3d020106052b8104002203620004') . $x . $y;
		}elseif(is_string($cpk)){
			$der = base64_decode($cpk, true);
			if($cpk === '' || preg_match('/^[A-Za-z0-9+\/]+={0,2}$/D', $cpk) !== 1 || $der === false ||
				rtrim(base64_encode($der), '=') !== rtrim($cpk, '=')){
				throw new TransportException('identity_key_invalid', 'Client SPKI must be valid base64');
			}
		}else{
			throw new TransportException('identity_key_invalid', 'Token cpk must be a JWK object or base64 SPKI string');
		}
		$key = openssl_pkey_get_public("-----BEGIN PUBLIC KEY-----\n" . base64_encode($der) . "\n-----END PUBLIC KEY-----\n");
		if($key === false){
			throw new TransportException('identity_key_invalid', 'OpenSSL rejected the client public key');
		}
		$details = openssl_pkey_get_details($key);
		if($details === false || $details['type'] !== OPENSSL_KEYTYPE_EC || ($details['ec']['curve_name'] ?? null) !== 'secp384r1'){
			throw new TransportException('identity_key_invalid', 'Client public key must use P-384');
		}
		$encoded = preg_replace('/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s/', '', $details['key']);
		$exported = $encoded === null ? false : base64_decode($encoded, true);
		if($exported === false || !hash_equals($exported, $der)){
			throw new TransportException('identity_key_invalid', 'Client SPKI is not an exact DER public key');
		}
		return [$key, $exported];
	}

	private static function derInteger(string $bytes) : string{
		$bytes = ltrim($bytes, "\0");
		if($bytes === '' || (ord($bytes[0]) & 0x80) !== 0){
			$bytes = "\0" . $bytes;
		}
		return "\x02" . chr(strlen($bytes)) . $bytes;
	}

	private static function verifySignature(string $input, string $signature, \OpenSSLAsymmetricKey $key, int $algorithm) : void{
		// -1 is truthy in php
		if(openssl_verify($input, $signature, $key, $algorithm) !== 1){
			throw new TransportException('identity_signature_invalid', 'Identity signature verification failed');
		}
	}

	private static function object(string $json) : \stdClass{
		$value = json_decode($json, false, 16, JSON_THROW_ON_ERROR);
		if(!$value instanceof \stdClass){
			throw new TransportException('identity_invalid', 'Expected a JSON object');
		}
		return $value;
	}

	private static function encode(string $bytes) : string{
		return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
	}

	private static function decode(string $value) : string{
		$bytes = base64_decode(strtr($value, '-_', '+/'), true);
		if($value === '' || preg_match('/^[A-Za-z0-9_-]+$/D', $value) !== 1 || $bytes === false || self::encode($bytes) !== $value){
			throw new TransportException('identity_invalid', 'Invalid base64url component');
		}
		return $bytes;
	}
}
