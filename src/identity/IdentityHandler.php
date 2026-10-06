<?php

declare(strict_types=1);

namespace amber\nethernet\identity;

use amber\nethernet\TransportException;

interface IdentityHandler{
	/** @param \Closure(?PeerIdentity, ?TransportException): void $complete @return \Closure(): void */
	public function verifyClient(string $token, string $canonicalFingerprints, string $detachedJws, \Closure $complete) : \Closure;

	public function signServer(string $canonicalFingerprints, int $now) : string;
}
