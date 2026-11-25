<?php

declare(strict_types=1);

namespace amber\nethernet\signaling;

/** @internal */
final class HttpSocket{
	public bool $reading = true;
	public string $output = '';
	public int $offset = 0;
	public HttpState $state = HttpState::HEADERS;
	// null until the first byte tells tls from plain http
	public ?bool $tls = false;
	public bool $handshaking = false;
	public bool $counted = false;

	/** @param resource $stream */
	public function __construct(public readonly mixed $stream, public readonly string $ip, public float $deadline){}
}
