<?php

declare(strict_types=1);

namespace amber\nethernet\backend;

use amber\nethernet\Channel;
use amber\nethernet\TransportConfig;
use amber\nethernet\TransportException;
use pmmp\webrtc\DataChannel;
use pmmp\webrtc\DataChannelOptions;
use pmmp\webrtc\GatheringState;
use pmmp\webrtc\PeerConnection;
use pmmp\webrtc\PeerConnectionOptions;
use pmmp\webrtc\WebRtcException;

final class ExtWebRtcPeer implements WebRtcPeer{
	private ?PeerConnection $peer = null;
	/** @var array<string, DataChannel> */
	private array $channels = [];
	private ?string $failureState = null;

	private function __clone(){}

	public static function assertAvailable() : void{
		if(!extension_loaded('webrtc')){
			throw new TransportException('backend_unavailable', 'ext-webrtc is not loaded');
		}
		$constants = (new \ReflectionExtension('webrtc'))->getConstants();
		if(phpversion('webrtc') !== '0.3.0' || ($constants['pmmp\\webrtc\\WEBRTC_VERSION'] ?? null) !== '0.24.5'){
			throw new TransportException('backend_incompatible', 'Expected ext-webrtc 0.3.0 with libdatachannel 0.24.5');
		}
		$required = [
			PeerConnectionOptions::class => ['create', 'setMaxMessageSize', 'setMaxReceiveQueueSize', 'setMaxReceiveQueueMessages', 'setMaxSendQueueSize', 'setMaxRemoteDescriptionSize', 'setMaxPendingDataChannels', 'setIceTcpEnabled'],
			PeerConnection::class => ['__construct', 'setRemoteOffer', 'setRemoteAnswer', 'getGatheringState', 'getLocalDescription', 'getState', 'getFailureState', 'getRemoteFingerprint', 'createDataChannel', 'pollDataChannels', 'close'],
			DataChannelOptions::class => ['create', 'setUnordered', 'setMaxRetransmits'],
			DataChannel::class => ['getLabel', 'getProtocol', 'isOpen', 'isClosed', 'isUnordered', 'getMaxRetransmits', 'getMaxPacketLifeTime', 'getMaxMessageSize', 'getBufferedAmount', 'getAvailableAmount', 'getQueuedMessageCount', 'send', 'peek', 'receive', 'close']
		];
		foreach($required as $class => $methods){
			if(!class_exists($class) || (new \ReflectionClass($class))->getExtensionName() !== 'webrtc'){
				throw new TransportException('backend_incompatible', 'Missing native class: ' . $class);
			}
			foreach($methods as $method){
				if(!method_exists($class, $method) || !(new \ReflectionMethod($class, $method))->isPublic()){
					throw new TransportException('backend_incompatible', 'Missing native method: ' . $class . '::' . $method);
				}
			}
		}
		if(!enum_exists(GatheringState::class) || !defined(GatheringState::class . '::COMPLETE')){
			throw new TransportException('backend_incompatible', 'Missing native gathering state');
		}
	}

	public function __construct(private readonly TransportConfig $config){
		self::assertAvailable();
		$this->peer = $this->native(function() : PeerConnection{
			$options = PeerConnectionOptions::create()
				->setMaxMessageSize($this->config->maxMessageBytes)
				->setMaxReceiveQueueSize($this->config->maxReceiveQueueBytes)
				->setMaxReceiveQueueMessages($this->config->maxReceiveQueueMessages)
				->setMaxSendQueueSize($this->config->maxSendQueueBytes)
				->setMaxRemoteDescriptionSize($this->config->maxSdpBytes)
				->setMaxPendingDataChannels($this->config->maxPendingChannels)
				->setIceTcpEnabled(false);
			return new PeerConnection($options);
		});
	}

	/**
	 * @template T
	 * @param \Closure(): T $operation
	 * @return T
	 */
	private function native(\Closure $operation, string $code = 'backend_error') : mixed{
		try{
			return $operation();
		}catch(WebRtcException | \ValueError $e){
			throw new TransportException($code, $e->getMessage(), $e);
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
		$this->native(fn() => $this->peer()->setRemoteOffer($sdp));
	}
	public function setRemoteAnswer(string $sdp) : void{
		$this->native(fn() => $this->peer()->setRemoteAnswer($sdp));
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
			if(!$nativeChannel instanceof DataChannel){
				$this->close();
				throw new TransportException('backend_incompatible', 'Invalid native channel result');
			}
			$channel = match($nativeChannel->getLabel()){
				'ReliableDataChannel' => Channel::RELIABLE,
				'UnreliableDataChannel' => Channel::UNRELIABLE,
				default => null
			};
			if($channel === null || isset($this->channels[$channel->name]) ||
				$nativeChannel->getProtocol() !== '' ||
				$nativeChannel->isUnordered() !== ($channel === Channel::UNRELIABLE) ||
				$nativeChannel->getMaxRetransmits() !== ($channel === Channel::UNRELIABLE ? 0 : null) ||
				$nativeChannel->getMaxPacketLifeTime() !== null){
				$nativeChannel->close();
				$this->close();
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
		return $this->native(function() use ($channel, $frame) : bool{
			$native = $this->channel($channel);
			if(!$native->isOpen()){
				throw new TransportException('closed', 'Native channel is not open');
			}
			$length = strlen($frame);
			if($length > $this->getMessageCapacity($channel)){
				throw new TransportException('payload_too_large', 'SCTP message exceeds negotiated capacity');
			}
			$buffered = $native->getBufferedAmount();
			if($buffered >= $this->config->maxSendQueueBytes || $length > $this->config->maxSendQueueBytes - $buffered){
				return false;
			}
			$native->send($frame);
			return true;
		}, 'native_send_failed');
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
			$this->native(function() : void{
				foreach($this->channels as $channel){
					$channel->close();
				}
			});
		}finally{
			$this->channels = [];
			$this->peer = null;
			$this->native(fn() => $peer->close());
		}
	}
	public function __destruct(){
		try{
			$this->close();
		}catch(\Throwable){
		}
	}
}
