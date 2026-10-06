<?php

declare(strict_types=1);

namespace amber\nethernet\identity;

use amber\nethernet\TransportConfig;
use amber\nethernet\TransportException;

final class SdpIdentity{
	private function __construct(
		public readonly string $sdpWithoutIdentity,
		public readonly string $canonicalFingerprints,
		public readonly ?string $token,
		public readonly ?string $detachedJws,
		public readonly ?string $providerDomain
	){}

	public static function fromSdp(string $sdp, TransportConfig $config) : self{
		if(strlen($sdp) > $config->maxSdpBytes || preg_match('//u', $sdp) !== 1 ||
			preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|\r(?!\n)/', $sdp) === 1){
			throw new TransportException('invalid_sdp', 'SDP exceeds limit or contains invalid text');
		}
		$lines = preg_split('/(?<=\n)/', $sdp);
		if($lines === false || rtrim($lines[0], "\r\n") !== 'v=0'){
			throw new TransportException('invalid_sdp', 'Expected SDP version zero');
		}
		/** @var list<array{algorithm: string, digest: string}> $fingerprints */
		$fingerprints = [];
		$clean = '';
		$attribute = null;
		$media = false;
		$scopeHasFingerprint = false;
		$candidates = 0;
		foreach($lines as $originalLine){
			$line = rtrim($originalLine, "\r\n");
			if(str_starts_with($line, 'm=')){
				$media = true;
				$scopeHasFingerprint = false;
			}
			if($line === 'a=identity' || str_starts_with($line, 'a=identity:')){
				if($line === 'a=identity' || $media || $attribute !== null){
					throw new TransportException('identity_invalid', 'Malformed, duplicate, or non-session identity attribute');
				}
				$attribute = substr($line, strlen('a=identity:'));
				continue;
			}
			if($line === 'a=fingerprint' || str_starts_with($line, 'a=fingerprint:')){
				if($scopeHasFingerprint || preg_match('/^a=fingerprint:(sha-256) ([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){31})$/D', $line, $match) !== 1){
					throw new TransportException('invalid_sdp', 'Invalid or duplicate SHA-256 fingerprint in SDP scope');
				}
				$scopeHasFingerprint = true;
				$fingerprints[] = ['algorithm' => $match[1], 'digest' => $match[2]];
			}
			if(str_starts_with($line, 'a=candidate:') && ++$candidates > $config->maxCandidates){
				throw new TransportException('invalid_sdp', 'Candidate count exceeds limit');
			}
			$clean .= $originalLine;
		}
		if($fingerprints === []){
			throw new TransportException('invalid_sdp', 'SDP has no supported fingerprint');
		}
		$canonical = json_encode(['fingerprint' => $fingerprints], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
		if($attribute === null){
			return new self($clean, $canonical, null, null, null);
		}
		$decoded = base64_decode($attribute, true);
		if($decoded === false || $attribute === '' || rtrim(base64_encode($decoded), '=') !== rtrim($attribute, '=') ||
			preg_match('/^[A-Za-z0-9+\/]+={0,2}$/D', $attribute) !== 1 || strlen($decoded) > $config->maxIdentityBytes){
			throw new TransportException('identity_invalid', 'Invalid or oversized identity envelope');
		}
		$envelope = self::jsonObject($decoded);
		$idp = $envelope->idp ?? null;
		$assertionText = $envelope->assertion ?? null;
		if(!$idp instanceof \stdClass || !isset($idp->domain) || !is_string($idp->domain) || $idp->domain === '' ||
			($idp->protocol ?? null) !== 'default' || !is_string($assertionText)){
			throw new TransportException('identity_invalid', 'Invalid identity provider or assertion fields');
		}
		$assertion = self::jsonObject($assertionText);
		$token = $assertion->token ?? null;
		$jws = $assertion->fingerprints ?? null;
		if(!is_string($token) || !is_string($jws)){
			throw new TransportException('identity_invalid', 'Token and fingerprint JWS must be strings');
		}
		$tokenParts = explode('.', $token);
		$jwsParts = explode('.', $jws);
		if(count($tokenParts) !== 3 || count($jwsParts) !== 3 || $jwsParts[1] !== ''){
			throw new TransportException('identity_invalid', 'Expected compact JWT and detached JWS');
		}
		foreach([$tokenParts[0], $tokenParts[1], $tokenParts[2], $jwsParts[0], $jwsParts[2]] as $part){
			self::decodeBase64Url($part);
		}
		foreach([$tokenParts[0], $jwsParts[0]] as $header){
			self::jsonObject(self::decodeBase64Url($header));
		}
		self::jsonObject(self::decodeBase64Url($tokenParts[1]));
		return new self($clean, $canonical, $token, $jws, $idp->domain);
	}

	private static function decodeBase64Url(string $value) : string{
		$decoded = base64_decode(strtr($value, '-_', '+/'), true);
		if($value === '' || preg_match('/^[A-Za-z0-9_-]+$/D', $value) !== 1 || $decoded === false ||
			rtrim(strtr(base64_encode($decoded), '+/', '-_'), '=') !== $value){
			throw new TransportException('identity_invalid', 'Invalid base64url component');
		}
		return $decoded;
	}

	private static function jsonObject(string $json) : \stdClass{
		try{
			$value = json_decode($json, false, 16, JSON_THROW_ON_ERROR);
		}catch(\JsonException $e){
			throw new TransportException('identity_invalid', 'Malformed or excessively nested identity JSON', $e);
		}
		if(!$value instanceof \stdClass){
			throw new TransportException('identity_invalid', 'Identity JSON must be an object');
		}
		self::rejectDuplicateKeys($json);
		return $value;
	}

	private static function rejectDuplicateKeys(string $json) : void{
		/** @var list<array<string, true>|null> $scopes */
		$scopes = [];
		$length = strlen($json);
		for($index = 0; $index < $length; ++$index){
			$token = $json[$index];
			if($token === '{' || $token === '['){
				$scopes[] = $token === '{' ? [] : null;
			}elseif($token === '}' || $token === ']'){
				array_pop($scopes);
			}elseif($token === '"'){
				$start = $index++;
				while($index < $length && $json[$index] !== '"'){
					$index += $json[$index] === '\\' ? 2 : 1;
				}
				$next = $index + 1;
				while($next < $length && str_contains(" \t\r\n", $json[$next])){
					++$next;
				}
				if($next >= $length || $json[$next] !== ':'){
					continue;
				}
				$key = json_decode(substr($json, $start, $index - $start + 1), true, 16, JSON_THROW_ON_ERROR);
				if(!is_string($key)){
					throw new TransportException('identity_invalid', 'Invalid JSON object key');
				}
				$scope = count($scopes) - 1;
				if(isset($scopes[$scope][$key])){
					throw new TransportException('identity_invalid', 'Duplicate identity JSON key');
				}
				$scopes[$scope][$key] = true;
			}
		}
	}
}
