<?php

declare(strict_types=1);

namespace amber\nethernet;

final class TransportConfig{
	public function __construct(
		public readonly int $maxHttpHeaderBytes = 8192,
		public readonly int $maxSdpBytes = 65536,
		public readonly int $maxCandidates = 64,
		public readonly int $maxIdentityBytes = 32768,
		public readonly int $maxNetworkIdBytes = 256,
		public readonly int $maxPendingNegotiations = 32,
		public readonly int $maxHttpConnections = 64,
		public readonly int $maxConnections = 128,
		public readonly int $maxMessageBytes = 262144,
		public readonly int $maxReceiveQueueBytes = 4194304,
		public readonly int $maxReceiveQueueMessages = 256,
		public readonly int $maxSendQueueBytes = 1048576,
		public readonly int $maxPendingChannels = 2,
		public readonly int $maxOutgoingQueueBytes = 4194304,
		public readonly int $maxOutgoingQueueMessages = 128,
		public readonly int $maxPayloadBytes = 4194304,
		public readonly int $maxFragments = 256,
		public readonly int $maxAggregateBytes = 67108864,
		public readonly int $httpHeaderTimeoutSeconds = 5,
		public readonly int $signalingTimeoutSeconds = 15,
		public readonly int $connectTimeoutSeconds = 15,
		public readonly int $assemblyTimeoutSeconds = 10,
		public readonly int $peerPollMessages = 32,
		public readonly int $peerPollBytes = 1048576,
		public readonly int $globalPollMessages = 256,
		public readonly int $globalPollBytes = 8388608
	){
		foreach(get_object_vars($this) as $name => $limit){
			if($limit < 1){
				throw new \InvalidArgumentException("$name must be positive; unlimited queues are not supported");
			}
		}
		if($maxMessageBytes < 2 || $maxMessageBytes > 268435456 || $maxFragments > 256){
			throw new \InvalidArgumentException('Message or fragment limit is outside wire/native bounds');
		}
		if($maxReceiveQueueBytes < $maxMessageBytes || $maxSendQueueBytes < $maxMessageBytes){
			throw new \InvalidArgumentException('Native queues must hold at least one maximum-size frame');
		}
		if($maxOutgoingQueueBytes < $maxPayloadBytes || $maxAggregateBytes < $maxPayloadBytes){
			throw new \InvalidArgumentException('Queue budgets must reserve a complete application message');
		}
		if($maxPendingChannels !== 2){
			throw new \InvalidArgumentException('NetherNet requires exactly two pending channel slots');
		}
	}
}
