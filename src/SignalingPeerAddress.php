<?php

declare(strict_types=1);

namespace amber\nethernet;

// trusted tcp signaling endpoint, distinct from the ice-selected endpoint
final class SignalingPeerAddress{
	public function __construct(public readonly string $ip, public readonly int $port){
		if(filter_var($ip, FILTER_VALIDATE_IP) === false || $port < 1 || $port > 65535){
			throw new \InvalidArgumentException('Signaling peer requires a numeric IP and a port within 1..65535');
		}
	}

	// php brackets ipv6 socket names
	public static function fromSocketName(string $name) : self{
		if(preg_match('~^(\[[0-9a-fA-F:.]+\]|[0-9.]+):([0-9]{1,5})$~D', $name, $parts) !== 1){
			throw new \InvalidArgumentException('Invalid signaling socket endpoint');
		}
		$ip = trim($parts[1], '[]');
		if(filter_var($ip, FILTER_VALIDATE_IP, $parts[1][0] === '[' ? FILTER_FLAG_IPV6 : FILTER_FLAG_IPV4) === false){
			throw new \InvalidArgumentException('Invalid signaling socket IP');
		}
		return new self($ip, (int) $parts[2]);
	}
}
