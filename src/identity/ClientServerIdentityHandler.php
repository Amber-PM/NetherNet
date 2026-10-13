<?php

declare(strict_types=1);

namespace amber\nethernet\identity;

use amber\nethernet\TransportConfig;
use amber\nethernet\TransportException;

final class ClientServerIdentityHandler implements IdentityHandler{
	/** @param \Closure(): int|null $clock */
	public function __construct(
		private readonly ClientIdentityVerifier $verifier,
		private readonly ServerIdentity $server,
		private readonly TransportConfig $config = new TransportConfig(),
		private readonly ?\Closure $clock = null
	){}

	/**
	 * @param \Closure(?PeerIdentity, ?TransportException): void $complete
	 * @return \Closure(): void
	 */
	public function verifyClient(string $token, string $canonicalFingerprints, string $detachedJws, \Closure $complete) : \Closure{
		$peer = null;
		$error = null;
		try{
			$identity = SdpIdentity::fromAssertion($token, $canonicalFingerprints, $detachedJws, $this->config);
			$peer = $this->verifier->verify($identity, $this->clock !== null ? ($this->clock)() : time());
		}catch(TransportException $e){
			$error = $e;
		}catch(\Throwable $e){
			$error = new TransportException('identity_verification_failed', 'Client verification failed', $e);
		}
		$complete($peer, $error);
		return static function() : void{};
	}

	public function signServer(string $canonicalFingerprints, int $now) : string{
		return $this->server->signServer($canonicalFingerprints, $now);
	}
}
