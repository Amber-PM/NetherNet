<?php

declare(strict_types=1);

namespace amber\nethernet\signaling;

use amber\nethernet\SignalingPeerAddress;

/** @internal */
final class HttpExchange{
	public HttpState $state = HttpState::HEADERS;
	public ?HttpResponse $response = null;
	public ?int $transportId = null;
	public bool $opened = false;
	public bool $dispatching = false;

	public function __construct(public ?HttpRequestParser $parser, public readonly ?SignalingPeerAddress $peerAddress = null){}
}
