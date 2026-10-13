<?php

declare(strict_types=1);

namespace amber\nethernet\tests\transport;

use amber\nethernet\identity\IdentityHandler;
use amber\nethernet\identity\PeerIdentity;
use amber\nethernet\identity\ServerIdentity;
use amber\nethernet\TransportException;

final class DeferredIdentityHandler implements IdentityHandler{
	/** @var \Closure(?PeerIdentity, ?TransportException): void|null */
	private ?\Closure $callback = null;
	public int $cancels = 0;
	public function __construct(private readonly ServerIdentity $server){}
	public function verifyClient(string $token, string $canonicalFingerprints, string $detachedJws, \Closure $complete) : \Closure{
		$this->callback = $complete;
		return function() : void{ ++$this->cancels; };
	}
	public function complete(?PeerIdentity $peer, ?TransportException $error) : void{
		($this->callback ?? throw new \LogicException('Not started'))($peer, $error);
	}
	public function signServer(string $canonicalFingerprints, int $now) : string{ return $this->server->signServer($canonicalFingerprints, $now); }
}
