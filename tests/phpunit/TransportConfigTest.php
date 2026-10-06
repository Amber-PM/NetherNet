<?php

declare(strict_types=1);

namespace amber\nethernet\tests;

use amber\nethernet\TransportConfig;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class TransportConfigTest extends TestCase{
	public function testBoundedConfigurationCanBeConstructed() : void{
		$config = new TransportConfig();
		self::assertGreaterThanOrEqual($config->maxMessageBytes, $config->maxReceiveQueueBytes);
		self::assertGreaterThanOrEqual($config->maxPayloadBytes, $config->maxOutgoingQueueBytes);
		self::assertLessThanOrEqual(256, $config->maxFragments);
	}

	/** @return iterable<string, array{array<string, int>}> */
	public static function invalidLimits() : iterable{
		foreach(['maxHttpHeaderBytes', 'maxSdpBytes', 'maxCandidates', 'maxIdentityBytes', 'maxNetworkIdBytes', 'maxPendingNegotiations', 'maxHttpConnections', 'maxConnections', 'maxMessageBytes', 'maxReceiveQueueBytes', 'maxReceiveQueueMessages', 'maxSendQueueBytes', 'maxPendingChannels', 'maxOutgoingQueueBytes', 'maxOutgoingQueueMessages', 'maxPayloadBytes', 'maxFragments', 'maxAggregateBytes', 'httpHeaderTimeoutSeconds', 'signalingTimeoutSeconds', 'connectTimeoutSeconds', 'assemblyTimeoutSeconds', 'peerPollMessages', 'peerPollBytes', 'globalPollMessages', 'globalPollBytes'] as $name){
			yield $name => [[$name => 0]];
		}
		yield 'header needs payload capacity' => [['maxMessageBytes' => 1]];
		yield 'native message upper bound' => [['maxMessageBytes' => 268435457]];
		yield 'countdown upper bound' => [['maxFragments' => 257]];
		yield 'receive cannot hold a frame' => [['maxReceiveQueueBytes' => 100]];
		yield 'send cannot hold a frame' => [['maxSendQueueBytes' => 100]];
		yield 'queue cannot reserve a message' => [['maxOutgoingQueueBytes' => 100]];
		yield 'aggregate cannot reserve a message' => [['maxAggregateBytes' => 100]];
		yield 'expected channels only' => [['maxPendingChannels' => 3]];
	}

	/** @param array<string, int> $limits */
	#[DataProvider('invalidLimits')]
	public function testRejectsUnboundedOrInconsistentLimits(array $limits) : void{
		$this->expectException(\InvalidArgumentException::class);
		new TransportConfig(...$limits);
	}
}
