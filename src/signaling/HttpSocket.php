<?php

declare(strict_types=1);

namespace amber\nethernet\signaling;

/** @internal */
final class HttpSocket{
	public bool $reading = true;
	public string $output = '';
	public int $offset = 0;
	public HttpState $state = HttpState::HEADERS;

	/** @param resource $stream */
	public function __construct(public readonly mixed $stream, public float $deadline){}
}
