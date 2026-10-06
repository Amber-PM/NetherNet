<?php

declare(strict_types=1);

namespace amber\nethernet\framing;

use amber\nethernet\Channel;
use amber\nethernet\TransportConfig;
use amber\nethernet\TransportException;

final class FrameCodec{
	/** @var list<string> */
	private array $chunks = [];
	private int $bufferedBytes = 0;
	private ?int $expectedRemaining = null;
	private ?float $startedAt = null;
	private float $lastNow = 0.0;

	public function __construct(private readonly TransportConfig $config){}

	/** @return \Generator<int, string, void, void> */
	public function encode(string $payload, int $messageCapacity) : \Generator{
		$this->validateCapacity($messageCapacity);
		$length = strlen($payload);
		$chunkSize = $messageCapacity - 1;
		$count = $length === 0 ? 1 : intdiv($length - 1, $chunkSize) + 1;
		if($length > $this->config->maxPayloadBytes || $count > $this->config->maxFragments){
			throw new TransportException('payload_too_large', 'Reliable message exceeds payload or fragment limit');
		}
		return $this->fragments($payload, $chunkSize, $count);
	}

	/** @return \Generator<int, string, void, void> */
	private function fragments(string $payload, int $chunkSize, int $count) : \Generator{
		for($index = 0; $index < $count; ++$index){
			yield chr($count - $index - 1) . substr($payload, $index * $chunkSize, $chunkSize);
		}
	}

	public function encodeUnreliable(string $payload, int $messageCapacity) : ?string{
		$this->validateCapacity($messageCapacity);
		if(strlen($payload) > min($messageCapacity - 1, $this->config->maxPayloadBytes)){
			return null;
		}
		return "\0" . $payload;
	}

	public function receive(string $frame, Channel $channel, int $messageCapacity, float $now) : ?string{
		$this->validateCapacity($messageCapacity);
		$this->expire($now);
		$frameLength = strlen($frame);
		if($frameLength === 0 || $frameLength > $messageCapacity){
			$this->fail('framing_invalid', 'Missing header or oversized SCTP frame');
		}
		$remaining = ord($frame[0]);
		$payloadLength = $frameLength - 1;
		if($channel === Channel::UNRELIABLE){
			if($remaining !== 0){
				$this->fail('framing_invalid', 'Unreliable messages cannot be fragmented');
			}
			if($payloadLength > $this->config->maxPayloadBytes){
				$this->fail('payload_too_large', 'Unreliable payload exceeds limit');
			}
			return substr($frame, 1);
		}
		if($this->expectedRemaining !== null && $remaining !== $this->expectedRemaining){
			$this->fail('framing_invalid', 'Reliable fragment countdown mismatch');
		}
		if($this->expectedRemaining === null && $remaining + 1 > $this->config->maxFragments){
			$this->fail('framing_invalid', 'Incoming fragment count exceeds limit');
		}
		if($payloadLength === 0 && ($remaining !== 0 || $this->isAssembling())){
			$this->fail('framing_invalid', 'Fragmented messages require nonempty fragments');
		}
		if($payloadLength > $this->config->maxPayloadBytes - $this->bufferedBytes){
			$this->fail('payload_too_large', 'Reliable assembly exceeds payload limit');
		}
		if(!$this->isAssembling() && $remaining === 0){
			return substr($frame, 1);
		}
		$this->startedAt ??= $now;
		$this->chunks[] = substr($frame, 1);
		$this->bufferedBytes += $payloadLength;
		if($remaining === 0){
			$payload = implode('', $this->chunks);
			$this->reset();
			return $payload;
		}
		$this->expectedRemaining = $remaining - 1;
		return null;
	}

	public function expire(float $now) : void{
		if(!is_finite($now) || $now < $this->lastNow){
			throw new \InvalidArgumentException('Clock must be finite, nonnegative, and monotonic');
		}
		$this->lastNow = $now;
		if($this->startedAt !== null && $now - $this->startedAt >= $this->config->assemblyTimeoutSeconds){
			$this->fail('framing_invalid', 'Reliable assembly timed out');
		}
	}

	public function isAssembling() : bool{ return $this->expectedRemaining !== null; }
	public function getBufferedBytes() : int{ return $this->bufferedBytes; }

	public function reset() : void{
		$this->chunks = [];
		$this->bufferedBytes = 0;
		$this->expectedRemaining = null;
		$this->startedAt = null;
	}

	private function validateCapacity(int $capacity) : void{
		if($capacity < 2 || $capacity > $this->config->maxMessageBytes){
			throw new \InvalidArgumentException('Negotiated message capacity is outside configured bounds');
		}
	}

	private function fail(string $code, string $reason) : never{
		$this->reset();
		throw new TransportException($code, $reason);
	}
}
