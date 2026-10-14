<?php

declare(strict_types=1);

namespace amber\nethernet;

// optional capability for existing Connection implementations
interface SignalingPeerConnection extends Connection{
	// null for admission without a trusted socket endpoint
	public function getSignalingPeerAddress() : ?SignalingPeerAddress;
}
