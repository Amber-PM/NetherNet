<?php

declare(strict_types=1);

namespace amber\nethernet\signaling;

final class TlsConfig{
	/** @var list<string> */
	public readonly array $names;
	public readonly int $expiresAt;

	/** @throws \InvalidArgumentException */
	public function __construct(
		public readonly string $certificateFile,
		public readonly string $privateKeyFile,
		public readonly bool $required = false,
		?int $now = null
	){
		if(!extension_loaded('openssl')){ throw new \InvalidArgumentException('TLS signaling requires ext-openssl'); }
		foreach([$certificateFile, $privateKeyFile] as $file){
			if(str_contains($file, "\0") || preg_match('~^[a-zA-Z][a-zA-Z0-9+.-]*://~', $file) === 1 || !is_file($file) || !is_readable($file)){
				throw new \InvalidArgumentException('TLS certificate and key must be readable local files');
			}
		}
		$chain = (string) file_get_contents($certificateFile, false, null, 0, 262145);
		$keyPem = (string) file_get_contents($privateKeyFile, false, null, 0, 65537);
		if(strlen($chain) > 262144 || strlen($keyPem) > 65536){ throw new \InvalidArgumentException('TLS certificate or key file is too large'); }
		$certificate = @openssl_x509_read($chain);
		$key = @openssl_pkey_get_private($keyPem);
		if($certificate === false){ throw new \InvalidArgumentException('TLS certificate file has no PEM certificate'); }
		if($key === false){ throw new \InvalidArgumentException('TLS key file has no unencrypted PEM private key'); }
		if(!openssl_x509_check_private_key($certificate, $key)){ throw new \InvalidArgumentException('TLS private key does not belong to the certificate'); }
		$details = openssl_pkey_get_details($key);
		if($details === false || ($details['type'] === OPENSSL_KEYTYPE_RSA && $details['bits'] < 2048) || ($details['type'] === OPENSSL_KEYTYPE_EC && $details['bits'] < 256)){
			throw new \InvalidArgumentException('TLS key is too weak, use RSA 2048 or P-256 and above');
		}
		$parsed = openssl_x509_parse($certificate);
		if($parsed === false || !is_int($parsed['validTo_time_t'] ?? null) || !is_int($parsed['validFrom_time_t'] ?? null)){
			throw new \InvalidArgumentException('TLS certificate could not be parsed');
		}
		$now ??= time();
		if($parsed['validFrom_time_t'] > $now || $parsed['validTo_time_t'] <= $now){ throw new \InvalidArgumentException('TLS certificate is expired or not valid yet'); }
		$this->expiresAt = $parsed['validTo_time_t'];
		$names = [];
		$alternative = $parsed['extensions']['subjectAltName'] ?? '';
		foreach(is_string($alternative) ? explode(',', $alternative) : [] as $entry){
			$entry = trim($entry);
			if(str_starts_with($entry, 'DNS:')){ $names[] = substr($entry, 4); }
			elseif(str_starts_with($entry, 'IP Address:')){ $names[] = substr($entry, 11); }
		}
		$common = $parsed['subject']['CN'] ?? null;
		if($names === [] && is_string($common)){ $names[] = $common; }
		$this->names = array_values(array_filter($names, static fn(string $name) : bool => preg_match('/^[A-Za-z0-9*:._-]{1,253}$/D', $name) === 1));
	}

	/** @return array<string, mixed> */
	public function contextOptions() : array{
		// the files are read on every handshake so a renewed certificate needs no restart
		return [
			'local_cert' => $this->certificateFile, 'local_pk' => $this->privateKeyFile,
			'crypto_method' => self::method(), 'disable_compression' => true, 'honor_cipher_order' => true,
			'security_level' => 2, 'verify_peer' => false, 'verify_peer_name' => false
		];
	}

	public static function method() : int{
		return STREAM_CRYPTO_METHOD_TLSv1_2_SERVER | STREAM_CRYPTO_METHOD_TLSv1_3_SERVER;
	}
}
