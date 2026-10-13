<?php

declare(strict_types=1);

namespace amber\nethernet\tests\identity;

use amber\nethernet\identity\ClientIdentityVerifier;
use amber\nethernet\identity\SdpIdentity;
use amber\nethernet\identity\ServerIdentity;
use amber\nethernet\TransportConfig;

final class IdentityFixture{
	public readonly \OpenSSLAsymmetricKey $issuer;
	public readonly ServerIdentity $server;

	public function __construct(){
		$this->issuer = self::key(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
		$this->server = new ServerIdentity(self::key(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']), 'operator.test', claims: ['sub' => 'player', 'iss' => 'issuer', 'aud' => 'game']);
	}

	/** @param array<string, int|string> $options */
	private static function key(array $options) : \OpenSSLAsymmetricKey{
		$key = openssl_pkey_new($options + ['config' => __DIR__ . '/openssl.cnf']);
		return $key !== false ? $key : throw new \RuntimeException('Key generation failed');
	}

	public function verifier() : ClientIdentityVerifier{
		$details = openssl_pkey_get_details($this->issuer);
		$public = $details !== false ? openssl_pkey_get_public($details['key']) : false;
		if($public === false){
			throw new \RuntimeException('Public key loading failed');
		}
		return new ClientIdentityVerifier(fn(?string $kid) => $public, 'issuer', 'game');
	}

	public function offer(string $sdp, int $now = 1000) : string{
		$parsed = SdpIdentity::fromSdp($sdp, new TransportConfig());
		$envelope = json_decode(base64_decode($this->server->signServer($parsed->canonicalFingerprints, $now), true) ?: throw new \RuntimeException('Envelope decoding failed'), true, 16, JSON_THROW_ON_ERROR);
		if(!is_array($envelope) || !is_string($envelope['assertion'] ?? null)){
			throw new \RuntimeException('Invalid envelope');
		}
		$assertion = json_decode($envelope['assertion'], true, 16, JSON_THROW_ON_ERROR);
		if(!is_array($assertion) || !is_string($assertion['token'] ?? null)){
			throw new \RuntimeException('Invalid assertion');
		}
		$parts = explode('.', $assertion['token']);
		$input = self::url('{"alg":"RS256"}') . '.' . $parts[1];
		if(!openssl_sign($input, $signature, $this->issuer, OPENSSL_ALGO_SHA256)){
			throw new \RuntimeException('Token signing failed');
		}
		$assertion['token'] = $input . '.' . self::url($signature);
		$envelope['assertion'] = json_encode($assertion, JSON_THROW_ON_ERROR);
		$attribute = base64_encode(json_encode($envelope, JSON_THROW_ON_ERROR));
		$end = strpos($sdp, "\n");
		if($end === false){
			throw new \RuntimeException('Missing version line ending');
		}
		return substr($sdp, 0, $end + 1) . "a=identity:$attribute\r\n" . substr($sdp, $end + 1);
	}

	private static function url(string $bytes) : string{
		return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
	}
}
