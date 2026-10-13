<?php

declare(strict_types=1);

namespace amber\nethernet\tests\transport;

use amber\nethernet\Channel;
use amber\nethernet\Connection;
use amber\nethernet\TransportListener;

final class RecordingListener implements TransportListener{
	/** @var list<string> */
	public array $events = [];
	/** @var array<int, Connection> */
	public array $connections = [];
	/** @var array<int, string> */
	public array $answers = [];
	/** @var list<array{int, string, Channel}> */
	public array $payloads = [];
	/** @var list<array{int, string, string}> */
	public array $closed = [];
	/** @var \Closure(Connection): void|null */
	public ?\Closure $opened = null;
	/** @var \Closure(int): void|null */
	public ?\Closure $answered = null;
	/** @var \Closure(Connection): void|null */
	public ?\Closure $received = null;

	public function onAnswer(int $id, string $answerSdp) : void{
		$this->events[] = 'answer';
		$this->answers[$id] = $answerSdp;
		if($this->answered !== null){ ($this->answered)($id); }
	}
	public function onOpen(Connection $connection) : void{
		$this->events[] = 'open';
		$this->connections[$connection->getId()] = $connection;
		if($this->opened !== null){ ($this->opened)($connection); }
	}
	public function onPayload(Connection $connection, string $payload, Channel $channel) : void{
		$this->payloads[] = [$connection->getId(), $payload, $channel];
		if($this->received !== null){ ($this->received)($connection); }
	}
	public function onClose(int $id, string $code, string $reason) : void{
		$this->events[] = 'close';
		$this->closed[] = [$id, $code, $reason];
	}
}
