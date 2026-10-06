<?php

declare(strict_types=1);

namespace amber\nethernet;

use amber\nethernet\identity\PeerIdentity;

interface Connection{
	public function getId() : int;
	public function getNetworkId() : string;
	public function getIdentity() : PeerIdentity;
	public function getState() : ConnectionState;

	/** @param \Closure(bool): void|null $accepted */
	public function send(string $payload, Channel $channel = Channel::RELIABLE, bool $immediate = false, ?\Closure $accepted = null) : SendResult;
	public function close(string $reason = 'local close') : void;
}
