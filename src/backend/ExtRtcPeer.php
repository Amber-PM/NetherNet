<?php

declare(strict_types=1);

namespace amber\nethernet\backend;

use amber\nethernet\Channel;
use amber\nethernet\TransportConfig;
use amber\nethernet\TransportException;
use amber\rtc\ConnectionState;
use amber\rtc\DataChannel;
use amber\rtc\DataChannelOptions;
use amber\rtc\GatheringState;
use amber\rtc\PeerConnection;
use amber\rtc\PeerConnectionOptions;
use amber\rtc\RtcException;
use amber\rtc\RtcRuntime;

final class ExtRtcPeer implements WebRtcPeer{
	private ?PeerConnection $peer = null;
	/** @var array<string, DataChannel> */
	private array $channels = [];
	private ?string $failureState = null;

	private function __clone(){}

	public static function assertAvailable() : void{
		if(!extension_loaded('rtc')){
			throw new TransportException('backend_unavailable', 'ext-rtc is not loaded');
		}
		$required = [
			RtcRuntime::class => ['getApiVersion', 'getCapabilities'],
			RtcException::class => [],
			PeerConnectionOptions::class => ['create', 'setMaxMessageSize', 'setMaxReceiveQueueSize', 'setMaxReceiveQueueMessages', 'setMaxSendQueueSize', 'setMaxRemoteDescriptionSize', 'setMaxPendingDataChannels', 'setIceTcpEnabled', 'setPortRange', 'setBindAddress', 'setIceUdpMuxEnabled'],
			PeerConnection::class => ['__construct', 'setRemoteOffer', 'setRemoteAnswer', 'getGatheringState', 'getLocalDescription', 'getState', 'getFailureState', 'getRemoteFingerprint', 'createDataChannel', 'pollDataChannels', 'close'],
			DataChannelOptions::class => ['create', 'setUnordered', 'setMaxRetransmits'],
			DataChannel::class => ['getLabel', 'getProtocol', 'isOpen', 'isClosed', 'isUnordered', 'getMaxRetransmits', 'getMaxPacketLifeTime', 'getMaxMessageSize', 'getBufferedAmount', 'getAvailableAmount', 'getQueuedMessageCount', 'send', 'peek', 'receive', 'close']
		];
		foreach($required as $class => $methods){
			if(!class_exists($class, false) || (new \ReflectionClass($class))->getExtensionName() !== 'rtc'){
				throw new TransportException('backend_incompatible', 'Missing native class: ' . $class);
			}
			foreach($methods as $method){
				if(!method_exists($class, $method) || !(new \ReflectionMethod($class, $method))->isPublic()){
					throw new TransportException('backend_incompatible', 'Missing native method: ' . $class . '::' . $method);
				}
			}
		}
		foreach([GatheringState::class => 'COMPLETE', ConnectionState::class => 'CONNECTED'] as $enum => $case){
			if(!enum_exists($enum, false) || (new \ReflectionClass($enum))->getExtensionName() !== 'rtc' || !defined($enum . '::' . $case)){
				throw new TransportException('backend_incompatible', 'Missing native enum: ' . $enum);
			}
		}
		$codes = ['CLOSED' => 2, 'INVALID_STATE' => 3, 'PAYLOAD_TOO_LARGE' => 6, 'BUFFER_BUDGET' => 10];
		foreach($codes as $name => $value){
			if(!defined(RtcException::class . '::' . $name) || constant(RtcException::class . '::' . $name) !== $value){
				throw new TransportException('backend_incompatible', 'Unexpected native error code: ' . $name);
			}
		}
		if(RtcRuntime::getApiVersion() !== 1){
			throw new TransportException('backend_incompatible', 'Expected ext-rtc API version 1');
		}
		$capabilities = RtcRuntime::getCapabilities();
		if($capabilities['peerConnection'] !== true || $capabilities['dataChannels'] !== true || $capabilities['observedRemoteFingerprint'] !== true){
			throw new TransportException('backend_incompatible', 'ext-rtc lacks peer, channel or fingerprint support');
		}
	}

	public function __construct(private readonly TransportConfig $config, int $icePortBegin = 0, int $icePortEnd = 0, ?string $bindAddress = null, bool $udpMux = false){
		if(($icePortBegin !== 0 || $icePortEnd !== 0) && ($icePortBegin < 1 || $icePortEnd < $icePortBegin || $icePortEnd > 65535)){
			throw new \InvalidArgumentException('ICE ports must both be zero, or an ordered range between 1 and 65535');
		}
		if($bindAddress !== null && filter_var($bindAddress, FILTER_VALIDATE_IP) === false){
			throw new \InvalidArgumentException('ICE bind address must be a numeric IPv4 or IPv6 address');
		}
		if($udpMux){
			self::assertMuxOptions($icePortBegin, $icePortEnd, $bindAddress, PHP_OS_FAMILY === 'Windows');
		}
		self::assertAvailable();
		$this->peer = $this->native(function() use ($icePortBegin, $icePortEnd, $bindAddress, $udpMux) : PeerConnection{
			$options = PeerConnectionOptions::create()
				->setMaxMessageSize($this->config->maxMessageBytes)
				->setMaxReceiveQueueSize($this->config->maxReceiveQueueBytes)
				->setMaxReceiveQueueMessages($this->config->maxReceiveQueueMessages)
				->setMaxSendQueueSize($this->config->maxSendQueueBytes)
				->setMaxRemoteDescriptionSize($this->config->maxSdpBytes)
				->setMaxPendingDataChannels($this->config->maxPendingChannels)
				->setIceTcpEnabled(false)
				->setBindAddress($bindAddress)
				->setIceUdpMuxEnabled($udpMux);
			if($icePortBegin !== 0){
				$options->setPortRange($icePortBegin, $icePortEnd);
			}
			return new PeerConnection($options);
		});
	}

	/** @throws \InvalidArgumentException */
	public static function assertMuxOptions(int $icePortBegin, int $icePortEnd, ?string $bindAddress, bool $windows) : void{
		if($icePortBegin === 0 || $icePortBegin !== $icePortEnd){
			throw new \InvalidArgumentException('ICE UDP mux requires one fixed ICE port');
		}
		// pinned libjuice on windows can stall the next mux negotiation ~60s after a wildcard mux peer closes
		if($windows && ($bindAddress === null || trim((string) inet_pton($bindAddress), "\0") === '')){
			throw new \InvalidArgumentException('ICE UDP mux on Windows requires an explicit, non-wildcard ICE bind address');
		}
	}

	/**
	 * @template T
	 * @param \Closure(): T $operation
	 * @return T
	 */
	private function native(\Closure $operation, string $code = 'backend_error') : mixed{
		try{
			return $operation();
		}catch(RtcException $e){
			throw new TransportException(match($e->getCode()){
				RtcException::CLOSED => 'closed',
				RtcException::PAYLOAD_TOO_LARGE => 'payload_too_large',
				default => $code
			}, $e->getMessage(), $e);
		}
	}

	private function peer() : PeerConnection{
		return $this->peer ?? throw new TransportException('closed', 'Native peer is closed');
	}

	private function channel(Channel $channel) : DataChannel{
		$this->peer();
		return $this->channels[$channel->name] ?? throw new TransportException('channel_unavailable', 'Channel has not been adopted');
	}

	public function setRemoteOffer(string $sdp) : void{
		$sdp = self::withoutUnusableCandidates($sdp);
		$this->native(fn() => $this->peer()->setRemoteOffer($sdp), 'negotiation_failed');
	}
	public function setRemoteAnswer(string $sdp) : void{
		$sdp = self::withoutUnusableCandidates($sdp);
		$this->native(fn() => $this->peer()->setRemoteAnswer($sdp), 'negotiation_failed');
	}

	// clients add tcp, mdns and rtcp (component 2, pion) candidates, ext-rtc rejects the whole sdp for them while ext-webrtc skipped them
	// malformed lines are kept so the native validator still rejects them
	private static function withoutUnusableCandidates(string $sdp) : string{
		$filtered = preg_replace_callback('/^a=candidate:\S+ ([12]) (\S+) \d+ (\S+) [1-9]\d{0,4} typ (?:host|srflx|prflx|relay)(?: [^\r\n]*)?(?:\r?\n|$)/m', static function(array $match) : string{
			return $match[1] === '1' && strtolower($match[2]) === 'udp' && filter_var($match[3], FILTER_VALIDATE_IP) !== false ? $match[0] : '';
		}, $sdp);
		return $filtered ?? throw new TransportException('negotiation_failed', 'Remote candidates could not be filtered');
	}
	public function isGatheringComplete() : bool{
		return $this->native(fn() => $this->peer()->getGatheringState() === GatheringState::COMPLETE);
	}
	public function getLocalDescription() : ?string{
		return $this->native(fn() => $this->peer()->getLocalDescription());
	}
	public function getRemoteFingerprint() : ?string{
		return $this->native(fn() => $this->peer()->getRemoteFingerprint());
	}
	public function getState() : string{
		return $this->peer === null ? 'CLOSED' : $this->native(fn() => $this->peer()->getState()->name);
	}
	public function getFailureState() : ?string{
		if($this->peer !== null){
			$this->failureState = $this->native(fn() => $this->peer()->getFailureState()?->name);
		}
		return $this->failureState;
	}

	public function createChannel(Channel $channel) : void{
		if(isset($this->channels[$channel->name])){
			throw new TransportException('channel_invalid', 'Duplicate local channel');
		}
		$this->channels[$channel->name] = $this->native(function() use ($channel) : DataChannel{
			$options = DataChannelOptions::create();
			if($channel === Channel::UNRELIABLE){
				$options->setUnordered(true)->setMaxRetransmits(0);
			}
			return $this->peer()->createDataChannel(self::label($channel), $options);
		});
	}

	private static function label(Channel $channel) : string{
		return $channel === Channel::RELIABLE ? 'ReliableDataChannel' : 'UnreliableDataChannel';
	}

	public function pollChannels() : array{
		$adopted = [];
		foreach($this->native(fn() => $this->peer()->pollDataChannels()) as $nativeChannel){
			$channel = $this->native(fn() => match($nativeChannel->getLabel()){
				'ReliableDataChannel' => Channel::RELIABLE,
				'UnreliableDataChannel' => Channel::UNRELIABLE,
				default => null
			});
			if($channel === null || isset($this->channels[$channel->name]) || !$this->native(fn() =>
				$nativeChannel->getProtocol() === '' &&
				$nativeChannel->isUnordered() === ($channel === Channel::UNRELIABLE) &&
				$nativeChannel->getMaxRetransmits() === ($channel === Channel::UNRELIABLE ? 0 : null) &&
				$nativeChannel->getMaxPacketLifeTime() === null)){
				try{
					$this->native(fn() => $nativeChannel->close());
				}finally{
					$this->close();
				}
				throw new TransportException('channel_invalid', 'Unexpected, duplicate, or incorrectly configured channel');
			}
			$this->channels[$channel->name] = $nativeChannel;
			$adopted[] = $channel;
		}
		return $adopted;
	}

	public function isChannelOpen(Channel $channel) : bool{
		if($this->peer === null || !isset($this->channels[$channel->name])){
			return false;
		}
		return $this->native(fn() => $this->channel($channel)->isOpen());
	}
	/** @return array{label: string, protocol: string, unordered: bool, maxRetransmits: int|null, maxPacketLifeTime: int|null, open: bool, closed: bool, bufferedBytes: int, availableBytes: int, queuedMessages: int} */
	public function getChannelInfo(Channel $channel) : array{
		return $this->native(function() use ($channel) : array{
			$native = $this->channel($channel);
			return [
				'label' => $native->getLabel(), 'protocol' => $native->getProtocol(),
				'unordered' => $native->isUnordered(), 'maxRetransmits' => $native->getMaxRetransmits(),
				'maxPacketLifeTime' => $native->getMaxPacketLifeTime(), 'open' => $native->isOpen(),
				'closed' => $native->isClosed(), 'bufferedBytes' => $native->getBufferedAmount(),
				'availableBytes' => $native->getAvailableAmount(), 'queuedMessages' => $native->getQueuedMessageCount()
			];
		});
	}
	public function getMessageCapacity(Channel $channel) : int{
		return $this->native(fn() => min($this->channel($channel)->getMaxMessageSize(), $this->config->maxMessageBytes));
	}
	public function sendFrame(Channel $channel, string $frame) : bool{
		$native = $this->channel($channel);
		if(strlen($frame) > $this->getMessageCapacity($channel)){
			throw new TransportException('payload_too_large', 'SCTP message exceeds negotiated capacity');
		}
		try{
			// false means the native per-peer send queue refused the frame
			return $native->send($frame);
		}catch(RtcException $e){
			// process-wide native budget, nothing was queued so the frame stays retryable
			if($e->getCode() === RtcException::BUFFER_BUDGET){
				return false;
			}
			throw new TransportException(match($e->getCode()){
				RtcException::CLOSED, RtcException::INVALID_STATE => 'closed',
				RtcException::PAYLOAD_TOO_LARGE => 'payload_too_large',
				default => 'native_send_failed'
			}, $e->getMessage(), $e);
		}
	}
	public function peekFrame(Channel $channel) : ?string{
		return $this->native(fn() => $this->channel($channel)->peek(), 'native_receive_failed');
	}
	public function receiveFrame(Channel $channel) : ?string{
		return $this->native(fn() => $this->channel($channel)->receive(), 'native_receive_failed');
	}
	public function close() : void{
		if($this->peer === null){
			return;
		}
		$peer = $this->peer;
		try{
			$this->getFailureState();
		}finally{
			$this->peer = null;
			try{
				// native close also closes the children
				$this->native(fn() => $peer->close());
			}finally{
				$this->channels = [];
			}
		}
	}
}
