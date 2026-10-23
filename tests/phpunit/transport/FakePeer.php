<?php

declare(strict_types=1);

namespace amber\nethernet\tests\transport;

use amber\nethernet\backend\WebRtcPeer;
use amber\nethernet\Channel;
use amber\nethernet\TransportException;

final class FakePeer implements WebRtcPeer{
	public const DIGEST = 'AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB';
	public const SDP = "v=0\r\no=rtc 1 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=fingerprint:sha-256 " . self::DIGEST . "\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
	public string $state = 'CONNECTED';
	public bool $gathered = true;
	public bool $open = true;
	public bool $blocked = false;
	public ?string $fingerprint = self::DIGEST;
	public ?string $localSdp = self::SDP;
	public int $capacity = 8;
	public int $closes = 0;
	public ?\Throwable $closeFailure = null;
	public ?string $remoteSdp = null;
	public ?TransportException $failure = null;
	/** @var list<array{Channel, string}> */
	public array $sent = [];
	/** @var array<string, list<string>> */
	public array $incoming = [];

	public function setRemoteOffer(string $sdp) : void{ $this->remoteSdp = $sdp; }
	public function setRemoteAnswer(string $sdp) : void{ $this->remoteSdp = $sdp; }
	public function isGatheringComplete() : bool{ return $this->gathered; }
	public function getLocalDescription() : ?string{ return $this->localSdp; }
	public function getRemoteFingerprint() : ?string{ return $this->fingerprint; }
	public function getState() : string{ return $this->state; }
	public function getFailureState() : ?string{ return null; }
	public function createChannel(Channel $channel) : void{}
	public function pollChannels() : array{ return []; }
	public function isChannelOpen(Channel $channel) : bool{ return $this->open; }
	public function getChannelInfo(Channel $channel) : array{
		return ['label' => $channel === Channel::RELIABLE ? 'ReliableDataChannel' : 'UnreliableDataChannel', 'protocol' => '', 'unordered' => $channel === Channel::UNRELIABLE, 'maxRetransmits' => $channel === Channel::UNRELIABLE ? 0 : null, 'maxPacketLifeTime' => null, 'open' => $this->open, 'closed' => !$this->open, 'bufferedBytes' => 0, 'availableBytes' => 0, 'queuedMessages' => 0];
	}
	public function getMessageCapacity(Channel $channel) : int{ return $this->capacity; }
	public function sendFrame(Channel $channel, string $frame) : bool{
		if($this->failure !== null){ throw $this->failure; }
		if($this->blocked){ return false; }
		$this->sent[] = [$channel, $frame];
		return true;
	}
	public function peekFrame(Channel $channel) : ?string{ return $this->incoming[$channel->name][0] ?? null; }
	public function receiveFrame(Channel $channel) : ?string{
		return isset($this->incoming[$channel->name]) ? array_shift($this->incoming[$channel->name]) : null;
	}
	public function close() : void{
		++$this->closes;
		$this->state = 'CLOSED';
		if($this->closeFailure !== null){ throw $this->closeFailure; }
	}
}
