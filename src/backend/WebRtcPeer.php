<?php

declare(strict_types=1);

namespace amber\nethernet\backend;

use amber\nethernet\Channel;

interface WebRtcPeer{
	public function setRemoteOffer(string $sdp) : void;
	public function setRemoteAnswer(string $sdp) : void;
	public function isGatheringComplete() : bool;
	public function getLocalDescription() : ?string;
	public function getRemoteFingerprint() : ?string;
	public function getState() : string;
	public function getFailureState() : ?string;

	public function createChannel(Channel $channel) : void;
	/** @return list<Channel> */
	public function pollChannels() : array;
	public function isChannelOpen(Channel $channel) : bool;
	/** @return array{label: string, protocol: string, unordered: bool, maxRetransmits: int|null, maxPacketLifeTime: int|null, open: bool, closed: bool, bufferedBytes: int, availableBytes: int, queuedMessages: int} */
	public function getChannelInfo(Channel $channel) : array;
	public function getMessageCapacity(Channel $channel) : int;
	public function sendFrame(Channel $channel, string $frame) : bool;
	public function peekFrame(Channel $channel) : ?string;
	public function receiveFrame(Channel $channel) : ?string;
	public function close() : void;
}
