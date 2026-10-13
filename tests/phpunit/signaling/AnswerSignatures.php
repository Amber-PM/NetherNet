<?php

declare(strict_types=1);

namespace amber\nethernet\tests\signaling;

use amber\nethernet\identity\SdpIdentity;
use PHPUnit\Framework\Assert;

final class AnswerSignatures{
	public static function verify(SdpIdentity $answer) : void{
		Assert::assertNotNull($answer->token);
		Assert::assertNotNull($answer->detachedJws);
		$token = explode('.', $answer->token);
		$claims = json_decode(self::decode($token[1]), true, 16, JSON_THROW_ON_ERROR);
		Assert::assertIsArray($claims);
		$jwk = $claims['cpk'];
		Assert::assertIsArray($jwk);
		Assert::assertSame('EC', $jwk['kty']);
		Assert::assertSame('P-384', $jwk['crv']);
		Assert::assertIsString($jwk['x']);
		Assert::assertIsString($jwk['y']);
		$der = hex2bin('3076301006072a8648ce3d020106052b8104002203620004') . self::decode($jwk['x']) . self::decode($jwk['y']);
		$key = openssl_pkey_get_public("-----BEGIN PUBLIC KEY-----\n" . base64_encode($der) . "\n-----END PUBLIC KEY-----\n");
		Assert::assertNotFalse($key);
		self::verifyCompact($answer->token, self::decode($token[1]), $key);
		self::verifyCompact($answer->detachedJws, $answer->canonicalFingerprints, $key);
	}

	private static function decode(string $value) : string{
		$result = base64_decode(strtr($value, '-_', '+/'), true);
		Assert::assertNotFalse($result);
		return $result;
	}

	private static function verifyCompact(string $compact, string $payload, \OpenSSLAsymmetricKey $key) : void{
		$parts = explode('.', $compact);
		Assert::assertSame(['alg' => 'ES384'], json_decode(self::decode($parts[0]), true, 16, JSON_THROW_ON_ERROR));
		$raw = self::decode($parts[2]);
		Assert::assertSame(96, strlen($raw));
		$body = '';
		foreach(str_split($raw, 48) as $scalar){
			$scalar = ltrim($scalar, "\0");
			if($scalar === '' || ord($scalar[0]) >= 128){ $scalar = "\0" . $scalar; }
			$body .= "\x02" . chr(strlen($scalar)) . $scalar;
		}
		$input = $parts[0] . '.' . rtrim(strtr(base64_encode($payload), '+/', '-_'), '=');
		Assert::assertSame(1, openssl_verify($input, "\x30" . chr(strlen($body)) . $body, $key, OPENSSL_ALGO_SHA384));
		Assert::assertSame(0, openssl_verify($input . 'X', "\x30" . chr(strlen($body)) . $body, $key, OPENSSL_ALGO_SHA384));
	}
}
