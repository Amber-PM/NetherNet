<?php

declare(strict_types=1);

namespace amber\nethernet;

interface TransportListener{
	public function onAnswer(int $id, string $answerSdp) : void;
	public function onOpen(Connection $connection) : void;
	public function onPayload(Connection $connection, string $payload, Channel $channel) : void;
	public function onClose(int $id, string $code, string $reason) : void;
}
