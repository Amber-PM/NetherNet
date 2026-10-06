<?php

declare(strict_types=1);

namespace amber\nethernet\identity;

final class PeerIdentity{
	/** @param array<string, mixed> $claims */
	public function __construct(
		public readonly string $subject,
		public readonly string $publicKeyDer,
		public readonly array $claims = []
	){}
}
