<?php

declare(strict_types=1);

namespace amber\nethernet\identity;

use amber\nethernet\TransportException;

final class ServerIdentity{
	private readonly \OpenSSLAsymmetricKey $privateKey;
	private readonly string $claimsJson;
	/** @var array{kty: string, crv: string, x: string, y: string} */
	private readonly array $publicJwk;

	/**
	 * @param array<string, mixed> $claims
	 * @throws \InvalidArgumentException
	 * @throws TransportException
	 */
	public function __construct(
		\OpenSSLAsymmetricKey|string $privateKey,
		private readonly string $domain,
		private readonly int $tokenLifetimeSeconds = 60,
		array $claims = [],
		?string $passphrase = null
	){
		if(!extension_loaded('openssl')){
			throw new TransportException('crypto_unavailable', 'Server identity signing requires ext-openssl');
		}
		if(strlen($domain) > 253 || preg_match('/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/D', $domain) !== 1){
			throw new \InvalidArgumentException('Operator domain must be an ASCII DNS name or single label');
		}
		if($tokenLifetimeSeconds < 1 || $tokenLifetimeSeconds > min(PHP_INT_MAX, 9007199254740991)){
			throw new \InvalidArgumentException('Token lifetime must fit exact positive integer arithmetic');
		}
		self::checkJsonData($claims);
		self::checkClaimNames($claims);
		if(array_key_exists('jti', $claims) && !is_string($claims['jti'])){
			throw new \InvalidArgumentException('JWT ID must be a string when present');
		}
		foreach(['iss', 'sub'] as $name){
			if(array_key_exists($name, $claims) && (!is_string($claims[$name]) || $claims[$name] === '')){
				throw new \InvalidArgumentException('Issuer and subject must be nonempty strings when present');
			}
		}
		if(array_key_exists('aud', $claims)){
			$aud = is_string($claims['aud']) ? [$claims['aud']] : $claims['aud'];
			if(!is_array($aud) || !array_is_list($aud) || $aud === []){
				throw new \InvalidArgumentException('Audience must be a nonempty string or string list');
			}
			foreach($aud as $value){
				if(!is_string($value) || $value === ''){
					throw new \InvalidArgumentException('Audience members must be nonempty strings');
				}
			}
		}
		if(array_key_exists('nbf', $claims) && (!is_int($claims['nbf']) || $claims['nbf'] < 0 || $claims['nbf'] > min(PHP_INT_MAX, 9007199254740991))){
			throw new \InvalidArgumentException('Not-before must be a nonnegative exact integer timestamp');
		}
		try{
			$encoded = json_encode((object) $claims, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR, 16);
		}catch(\JsonException){
			throw new \InvalidArgumentException('Claims must be valid bounded JSON data');
		}
		if(strlen($encoded) > 8192){
			throw new \InvalidArgumentException('Additional claims exceed 8192 bytes');
		}
		$this->claimsJson = $encoded;
		if(is_string($privateKey)){
			// openssl also accepts file urls
			if(strlen($privateKey) > 16384 || !str_starts_with($privateKey, '-----BEGIN ')){
				throw new \InvalidArgumentException('Expected private PEM text');
			}
			$loaded = @openssl_pkey_get_private($privateKey, $passphrase ?? '');
			if($loaded === false){
				throw new \InvalidArgumentException('OpenSSL rejected the private PEM or passphrase');
			}
			$privateKey = $loaded;
		}elseif($passphrase !== null){
			throw new \InvalidArgumentException('Passphrase applies only to PEM text');
		}
		$details = openssl_pkey_get_details($privateKey);
		if($details === false || $details['type'] !== OPENSSL_KEYTYPE_EC || ($details['ec']['curve_name'] ?? null) !== 'secp384r1'){
			throw new \InvalidArgumentException('Operator private key must use P-384');
		}
		foreach(['d', 'x', 'y'] as $component){
			$value = $details['ec'][$component] ?? null;
			if(!is_string($value) || $value === '' || strlen($value) > 48){
				throw new \InvalidArgumentException('Operator key must contain private P-384 components');
			}
		}
		// openssl can load mismatched ec key components
		$public = @openssl_pkey_get_public($details['key']);
		$probe = 'NetherNet operator key consistency';
		if($public === false || !@openssl_sign($probe, $signature, $privateKey, OPENSSL_ALGO_SHA384) ||
			@openssl_verify($probe, $signature, $public, OPENSSL_ALGO_SHA384) !== 1){
			throw new \InvalidArgumentException('Operator private and public key components must match and support ES384');
		}
		$this->privateKey = $privateKey;
		$this->publicJwk = ['kty' => 'EC', 'crv' => 'P-384', 'x' => self::encode(str_pad($details['ec']['x'], 48, "\0", STR_PAD_LEFT)), 'y' => self::encode(str_pad($details['ec']['y'], 48, "\0", STR_PAD_LEFT))];
	}

	/**
	 * @throws \InvalidArgumentException
	 * @throws TransportException
	 */
	public function signServer(string $canonicalFingerprints, int $now) : string{
		if($now < 0 || $now > min(PHP_INT_MAX, 9007199254740991) - $this->tokenLifetimeSeconds){
			throw new \InvalidArgumentException('Issue and expiry times must fit exact integer arithmetic');
		}
		self::checkFingerprints($canonicalFingerprints);
		$claims = json_decode($this->claimsJson, false, 16, JSON_THROW_ON_ERROR);
		if(!$claims instanceof \stdClass){
			throw new TransportException('identity_signing_failed', 'Invalid stored claims');
		}
		if(isset($claims->nbf) && $claims->nbf > $now){
			throw new \InvalidArgumentException('Not-before cannot exceed issue time');
		}
		$claims->cpk = $this->publicJwk;
		$claims->iat = $now;
		$claims->exp = $now + $this->tokenLifetimeSeconds;
		$header = self::encode('{"alg":"ES384"}');
		$input = $header . '.' . self::encode(json_encode($claims, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR, 16));
		$token = $input . '.' . self::encode($this->sign($input));
		$jws = $header . '..' . self::encode($this->sign($header . '.' . self::encode($canonicalFingerprints)));
		$assertion = json_encode(['token' => $token, 'fingerprints' => $jws], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
		return base64_encode(json_encode(['idp' => ['domain' => $this->domain, 'protocol' => 'default'], 'assertion' => $assertion], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
	}

	private function sign(string $input) : string{
		if(!@openssl_sign($input, $signature, $this->privateKey, OPENSSL_ALGO_SHA384)){
			throw new TransportException('identity_signing_failed', 'OpenSSL failed to sign the server identity');
		}
		return self::joseSignature($signature);
	}

	private static function joseSignature(string $der) : string{
		// p-384 signatures fit short-form der lengths
		$size = strlen($der);
		if($size < 8 || $size > 104 || $der[0] !== "\x30" || ord($der[1]) !== $size - 2){
			throw new TransportException('identity_signing_failed', 'Invalid ES384 DER sequence');
		}
		$offset = 2;
		$raw = '';
		for($index = 0; $index < 2; ++$index){
			if($offset + 2 > $size || $der[$offset++] !== "\x02"){
				throw new TransportException('identity_signing_failed', 'Invalid ES384 DER integer');
			}
			$length = ord($der[$offset++]);
			if($length < 1 || $length > 49 || $offset + $length > $size){
				throw new TransportException('identity_signing_failed', 'Invalid ES384 scalar length');
			}
			$scalar = substr($der, $offset, $length);
			$offset += $length;
			if((ord($scalar[0]) & 0x80) !== 0 || ($length > 1 && $scalar[0] === "\0" && (ord($scalar[1]) & 0x80) === 0)){
				throw new TransportException('identity_signing_failed', 'Noncanonical ES384 DER integer');
			}
			$scalar = ltrim($scalar, "\0");
			if($scalar === '' || strlen($scalar) > 48){
				throw new TransportException('identity_signing_failed', 'Invalid ES384 scalar');
			}
			$raw .= str_pad($scalar, 48, "\0", STR_PAD_LEFT);
		}
		if($offset !== $size){
			throw new TransportException('identity_signing_failed', 'Trailing ES384 DER data');
		}
		return $raw;
	}

	private static function checkFingerprints(string $json) : void{
		if(strlen($json) > 65536){
			throw new \InvalidArgumentException('Canonical fingerprints exceed 65536 bytes');
		}
		try{
			$value = json_decode($json, false, 16, JSON_THROW_ON_ERROR);
		}catch(\JsonException){
			throw new \InvalidArgumentException('Malformed fingerprint JSON');
		}
		if(!$value instanceof \stdClass || array_keys(get_object_vars($value)) !== ['fingerprint'] || !is_array($value->fingerprint) || !array_is_list($value->fingerprint) || $value->fingerprint === []){
			throw new \InvalidArgumentException('Expected a nonempty canonical fingerprint list');
		}
		$fingerprints = [];
		foreach($value->fingerprint as $fingerprint){
			if(!$fingerprint instanceof \stdClass || array_keys(get_object_vars($fingerprint)) !== ['algorithm', 'digest'] || $fingerprint->algorithm !== 'sha-256' || !is_string($fingerprint->digest) || preg_match('/^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){31}$/D', $fingerprint->digest) !== 1){
				throw new \InvalidArgumentException('Expected canonical SHA-256 fingerprints');
			}
			$fingerprints[] = ['algorithm' => 'sha-256', 'digest' => $fingerprint->digest];
		}
		// reject duplicate keys and alternate escaping
		if(json_encode(['fingerprint' => $fingerprints], JSON_THROW_ON_ERROR) !== $json){
			throw new \InvalidArgumentException('Fingerprint JSON is not canonical');
		}
	}

	/** @param array<array-key, mixed> $claims */
	private static function checkClaimNames(array $claims) : void{
		foreach($claims as $name => $value){
			if(!is_string($name) || $name === '' || in_array($name, ['cpk', 'iat', 'exp'], true)){
				throw new \InvalidArgumentException('Claims must have nonempty names and cannot override cpk, iat or exp');
			}
		}
	}

	private static function checkJsonData(mixed $value, int $depth = 0) : void{
		if($depth > 12){
			throw new \InvalidArgumentException('Additional claims are excessively nested');
		}
		if(is_array($value)){
			foreach($value as $child){
				self::checkJsonData($child, $depth + 1);
			}
		}elseif(!(is_null($value) || is_bool($value) || is_int($value) || is_string($value) || (is_float($value) && is_finite($value)))){
			throw new \InvalidArgumentException('Claims must contain only JSON scalar and array data');
		}
	}

	private static function encode(string $bytes) : string{
		return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
	}
}
