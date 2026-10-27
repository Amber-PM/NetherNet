<?php

declare(strict_types=1);

namespace amber\nethernet;

final class ConnectionStats{
	public function __construct(
		public readonly ?int $rttMs,
		public readonly int $bytesSent,
		public readonly int $bytesReceived,
		public readonly int $sendQueueBytes,
		public readonly int $receiveQueueBytes
	){}
}
