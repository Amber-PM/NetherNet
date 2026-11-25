<?php

declare(strict_types=1);

namespace amber\nethernet\signaling;

use amber\nethernet\SignalingPeerAddress;

/** @internal */
final class ProxyProtocol{
	private const V2_SIGNATURE = "\r\n\r\n\0\r\nQUIT\n";
	public const MAX_BYTES = 16 + 512;

	/**
	 * @return array{?SignalingPeerAddress, int}|null
	 * @throws \InvalidArgumentException
	 */
	public static function parse(string $buffer) : ?array{
		$size = strlen($buffer);
		if($size >= 12 ? str_starts_with($buffer, self::V2_SIGNATURE) : str_starts_with(self::V2_SIGNATURE, $buffer)){
			return self::parseV2($buffer);
		}
		if($size >= 6 ? !str_starts_with($buffer, 'PROXY ') : !str_starts_with('PROXY ', $buffer)){
			throw new \InvalidArgumentException('Missing PROXY header');
		}
		$end = strpos($buffer, "\r\n");
		if($end === false){
			if($size >= 107){ throw new \InvalidArgumentException('PROXY v1 header exceeds 107 bytes'); }
			return null;
		}
		if($end > 105){ throw new \InvalidArgumentException('PROXY v1 header exceeds 107 bytes'); }
		$line = substr($buffer, 0, $end);
		if(str_starts_with($line, 'PROXY UNKNOWN')){
			return [null, $end + 2];
		}
		if(preg_match('/^PROXY TCP([46]) ([0-9a-fA-F:.]+) ([0-9a-fA-F:.]+) ([0-9]{1,5}) ([0-9]{1,5})$/D', $line, $parts) !== 1 ||
			filter_var($parts[2], FILTER_VALIDATE_IP, $parts[1] === '4' ? FILTER_FLAG_IPV4 : FILTER_FLAG_IPV6) === false){
			throw new \InvalidArgumentException('Malformed PROXY v1 header');
		}
		return [new SignalingPeerAddress($parts[2], (int) $parts[4]), $end + 2];
	}

	/** @return array{?SignalingPeerAddress, int}|null */
	private static function parseV2(string $buffer) : ?array{
		if(strlen($buffer) < 16){ return null; }
		$command = ord($buffer[12]);
		$family = ord($buffer[13]);
		$length = (ord($buffer[14]) << 8) | ord($buffer[15]);
		if(($command & 0xf0) !== 0x20 || ($command & 0x0f) > 1 || $length > self::MAX_BYTES - 16){
			throw new \InvalidArgumentException('Unsupported PROXY v2 header');
		}
		if(strlen($buffer) < 16 + $length){ return null; }
		// local command is the proxy's own health check
		if(($command & 0x0f) === 0){
			return [null, 16 + $length];
		}
		$bytes = match($family){ 0x11 => 4, 0x21 => 16, default => throw new \InvalidArgumentException('PROXY v2 requires TCP over IPv4 or IPv6') };
		if($length < 2 * $bytes + 4){ throw new \InvalidArgumentException('Truncated PROXY v2 addresses'); }
		$ip = inet_ntop(substr($buffer, 16, $bytes));
		$port = (ord($buffer[16 + 2 * $bytes]) << 8) | ord($buffer[17 + 2 * $bytes]);
		if($ip === false){ throw new \InvalidArgumentException('Malformed PROXY v2 address'); }
		return [new SignalingPeerAddress($ip, $port), 16 + $length];
	}

	/** @param list<string> $networks */
	public static function assertNetworks(array $networks) : void{
		foreach($networks as $network){
			$parts = explode('/', $network, 2);
			$address = $parts[0];
			$bits = $parts[1] ?? null;
			$packed = filter_var($address, FILTER_VALIDATE_IP) === false ? false : inet_pton($address);
			if($packed === false || ($bits !== null && (preg_match('/^[0-9]{1,3}$/D', $bits) !== 1 || (int) $bits > strlen($packed) * 8))){
				throw new \InvalidArgumentException('Trusted proxies must be numeric IP addresses or CIDR networks');
			}
		}
	}

	/** @param list<string> $networks */
	public static function matches(string $ip, array $networks) : bool{
		$packed = inet_pton($ip);
		if($packed === false){ return false; }
		// a dual-stack listener reports ipv4 peers as ::ffff:a.b.c.d
		if(strlen($packed) === 16 && str_starts_with($packed, "\0\0\0\0\0\0\0\0\0\0\xff\xff")){ $packed = substr($packed, 12); }
		foreach($networks as $network){
			$parts = explode('/', $network, 2);
			$address = $parts[0];
			$bits = $parts[1] ?? null;
			$base = inet_pton($address);
			if($base === false || strlen($base) !== strlen($packed)){ continue; }
			$bits = $bits === null ? strlen($base) * 8 : (int) $bits;
			$whole = intdiv($bits, 8);
			if(substr($base, 0, $whole) !== substr($packed, 0, $whole)){ continue; }
			$rest = $bits % 8;
			if($rest === 0 || ((ord($base[$whole]) ^ ord($packed[$whole])) & (0xff << (8 - $rest) & 0xff)) === 0){ return true; }
		}
		return false;
	}
}
