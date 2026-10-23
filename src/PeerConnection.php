<?php

declare(strict_types=1);

namespace amber\nethernet;

use amber\nethernet\backend\WebRtcPeer;
use amber\nethernet\framing\FrameCodec;
use amber\nethernet\identity\IdentityHandler;
use amber\nethernet\identity\PeerIdentity;
use amber\nethernet\identity\SdpIdentity;
use amber\nethernet\internal\TransportBudget;
use amber\nethernet\internal\TransportCleanupException;

final class PeerConnection implements SignalingPeerConnection{
	private ConnectionState $state = ConnectionState::VERIFYING;
	private ?PeerIdentity $identity = null;
	private ?TransportException $verificationError = null;
	private bool $verified = false;
	/** @var \Closure(): void|null */
	private ?\Closure $cancel = null;
	private ?WebRtcPeer $peer = null;
	private ?SdpIdentity $offer;
	private readonly FrameCodec $codec;
	private readonly string $fingerprint;
	private int $outgoingBytes = 0;
	private int $receiveReserved = 0;
	private int $workMessages = 0;
	private int $workBytes = 0;
	private int $workGeneration = -1;
	private bool $flushing = false;
	private int $channelCursor = 0;
	private bool $sendFirst = true;
	/** @var \SplQueue<array{frames: \Generator<int, string, void, void>, bytes: int, complete: \Closure(bool): void|null}> */
	private \SplQueue $outgoing;

	/**
	 * @param \Closure(): WebRtcPeer $factory
	 * @param \Closure(): int $wallClock
	 * @param \Closure(int): void $closed
	 */
	public function __construct(
		private readonly int $id,
		private readonly string $networkId,
		SdpIdentity $offer,
		private readonly TransportConfig $config,
		private readonly IdentityHandler $handler,
		private readonly TransportListener $listener,
		private readonly \Closure $factory,
		private readonly \Closure $wallClock,
		private readonly TransportBudget $budget,
		private float $startedAt,
		private readonly \Closure $closed,
		private readonly ?SignalingPeerAddress $signalingPeerAddress = null
	){
		$this->offer = $offer;
		$this->codec = new FrameCodec($config);
		$this->outgoing = new \SplQueue();
		$canonical = json_decode($offer->canonicalFingerprints, true, 16, JSON_THROW_ON_ERROR);
		if(!is_array($canonical) || !is_array($canonical['fingerprint'] ?? null)){
			throw new TransportException('identity_invalid', 'Invalid parsed fingerprints');
		}
		$digest = null;
		foreach($canonical['fingerprint'] as $entry){
			if(!is_array($entry) || !is_string($entry['digest'] ?? null)){
				throw new TransportException('identity_invalid', 'Invalid parsed fingerprint');
			}
			$value = strtoupper($entry['digest']);
			if($digest !== null && $digest !== $value){
				throw new TransportException('identity_fingerprint_mismatch', 'The data-only profile requires one DTLS certificate');
			}
			$digest = $value;
		}
		$this->fingerprint = $digest ?? throw new TransportException('identity_missing', 'No authenticated fingerprint');
	}

	public function getId() : int{ return $this->id; }
	public function getNetworkId() : string{ return $this->networkId; }
	public function getSignalingPeerAddress() : ?SignalingPeerAddress{ return $this->signalingPeerAddress; }
	public function getIdentity() : PeerIdentity{ return $this->identity ?? throw new TransportException('identity_missing', 'Peer is not authenticated'); }
	public function getState() : ConnectionState{ return $this->state; }

	public function startVerification() : void{
		$offer = $this->offer ?? throw new \LogicException('Verification has no offer');
		$reference = \WeakReference::create($this);
		try{
			$cancel = $this->handler->verifyClient($offer->token ?? '', $offer->canonicalFingerprints, $offer->detachedJws ?? '', static function(?PeerIdentity $identity, ?TransportException $error) use ($reference) : void{
				$connection = $reference->get();
				if($connection === null || $connection->state !== ConnectionState::VERIFYING || $connection->verified){ return; }
				$connection->verified = true;
				$connection->cancel = null;
				$connection->identity = $identity;
				$connection->verificationError = ($identity === null) === ($error === null) ? new TransportException('identity_verification_failed', 'Verifier must supply exactly one result') : $error;
			});
		}catch(\Throwable $e){
			$this->verified = true;
			$this->verificationError = $e instanceof TransportException ? $e : new TransportException('identity_verification_failed', 'Verifier failed', $e);
			return;
		}
		if($this->state === ConnectionState::CLOSED){ $this->notify($cancel); }
		elseif(!$this->verified){ $this->cancel = $cancel; }
	}

	public function poll(float $now) : void{
		if($this->state === ConnectionState::CLOSED){ return; }
		$this->syncWork();
		try{
			$event = $this->advance($now);
		}catch(\Throwable $e){
			$this->fail($e);
			return;
		}
		if($event !== null){
			$this->notify(function() use ($event) : void{
				if(is_string($event)){ $this->listener->onAnswer($this->id, $event); }
				else{ $this->listener->onOpen($this); }
			});
		}
		if($this->state !== ConnectionState::OPEN){ return; }
		$sendFirst = $this->sendFirst;
		$messages = $this->workMessages;
		try{
			$this->pollOpen($now, $sendFirst);
		}finally{
			if($this->workMessages > $messages){ $this->sendFirst = !$sendFirst; }
		}
	}

	private function pollOpen(float $now, bool $sendFirst) : void{
		if($sendFirst){ $this->flush(); }
		$channels = [Channel::RELIABLE, Channel::UNRELIABLE];
		while($this->state === ConnectionState::OPEN){
			$progress = false;
			for($offset = 0; $offset < 2 && $this->state === ConnectionState::OPEN; ++$offset){
				$channel = $channels[($this->channelCursor + $offset) % 2];
				try{
					$frame = $this->backend()->peekFrame($channel);
					if($frame === null){ continue; }
					if($frame === '' || strlen($frame) > $this->backend()->getMessageCapacity($channel)){
						throw new TransportException('framing_invalid', 'Missing header or oversized SCTP frame');
					}
					if(!$this->canWork(strlen($frame))){ continue; }
					$this->consume(strlen($frame));
					$received = $this->backend()->receiveFrame($channel);
					if($received !== $frame){ throw new TransportException('native_receive_failed', 'Peek and receive disagree'); }
					$payload = $this->decode($frame, $channel, $now);
				}catch(\Throwable $e){
					$this->fail($e);
					return;
				}
				$progress = true;
				if($payload !== null){ $this->notify(fn() => $this->listener->onPayload($this, $payload, $channel)); }
			}
			if(!$progress){ break; }
		}
		$this->channelCursor = ($this->channelCursor + 1) % 2;
		if(!$sendFirst && $this->state === ConnectionState::OPEN){ $this->flush(); }
	}

	private function backend() : WebRtcPeer{ return $this->peer ?? throw new TransportException('closed', 'Peer is closed'); }

	private function advance(float $now) : string|bool|null{
		if($this->state === ConnectionState::VERIFYING || $this->state === ConnectionState::GATHERING){
			if($now - $this->startedAt >= $this->config->signalingTimeoutSeconds){ throw new TransportException('signaling_timeout', 'Identity verification or ICE gathering timed out'); }
		}
		if($this->state === ConnectionState::VERIFYING){
			if(!$this->verified){ return null; }
			if($this->verificationError !== null){ throw $this->verificationError; }
			$this->peer = ($this->factory)();
			$this->peer->setRemoteOffer(($this->offer ?? throw new \LogicException('Missing verified offer'))->sdpWithoutIdentity);
			$this->offer = null;
			$this->state = ConnectionState::GATHERING;
			return null;
		}
		$peer = $this->backend();
		if($peer->getFailureState() !== null || in_array($peer->getState(), ['FAILED', 'DISCONNECTED', 'CLOSED'], true)){
			throw new TransportException('backend_failed', 'Native peer failed or disconnected');
		}
		if($this->state === ConnectionState::GATHERING){
			if(!$peer->isGatheringComplete()){ return null; }
			$sdp = $peer->getLocalDescription() ?? throw new TransportException('invalid_sdp', 'Missing gathered answer');
			$parsed = SdpIdentity::fromSdp($sdp, $this->config);
			if($parsed->token !== null){ throw new TransportException('identity_invalid', 'Native answer must not supply identity'); }
			$offset = $this->answerIdentityOffset($sdp);
			$assertion = $this->handler->signServer($parsed->canonicalFingerprints, ($this->wallClock)());
			$ending = substr($sdp, $offset - 2, 2) === "\r\n" ? "\r\n" : "\n";
			$answer = substr($sdp, 0, $offset) . 'a=identity:' . $assertion . $ending . substr($sdp, $offset);
			$final = SdpIdentity::fromSdp($answer, $this->config);
			if($final->token === null || $final->canonicalFingerprints !== $parsed->canonicalFingerprints || $final->sdpWithoutIdentity !== $sdp){
				throw new TransportException('identity_signing_failed', 'Signer returned an invalid identity envelope');
			}
			$this->state = ConnectionState::CONNECTING;
			$this->startedAt = $now;
			return $answer;
		}
		$peer->pollChannels();
		if($this->state === ConnectionState::CONNECTING){
			if($now - $this->startedAt >= $this->config->connectTimeoutSeconds){ throw new TransportException('connect_timeout', 'DTLS or channels timed out'); }
			if($peer->getState() !== 'CONNECTED' || !$peer->isChannelOpen(Channel::RELIABLE) || !$peer->isChannelOpen(Channel::UNRELIABLE)){ return null; }
			$fingerprint = $peer->getRemoteFingerprint();
			if($fingerprint === null || !hash_equals($this->fingerprint, strtoupper($fingerprint))){
				throw new TransportException('identity_fingerprint_mismatch', 'Connected DTLS fingerprint differs from authenticated offer');
			}
			$this->state = ConnectionState::OPEN;
			return true;
		}
		foreach(Channel::cases() as $channel){
			if(!$peer->isChannelOpen($channel)){ throw new TransportException('closed', 'Required data channel closed'); }
		}
		$this->codec->expire($now);
		return null;
	}

	private function answerIdentityOffset(string $sdp) : int{
		$lines = preg_split('/(?<=\n)/', $sdp);
		if($lines === false){ throw new TransportException('invalid_sdp', 'Cannot split answer lines'); }
		$offset = 0;
		$mediaOffset = null;
		$last = -1;
		$seen = [];
		$fingerprint = null;
		foreach($lines as $original){
			if($original === ''){ continue; }
			$line = rtrim($original, "\r\n");
			if(strlen($line) < 3 || $line[1] !== '='){ throw new TransportException('invalid_sdp', 'Malformed answer field'); }
			$type = $line[0];
			if($type === 'm'){
				if(preg_match('/^m=application [0-9]+ UDP\/DTLS\/SCTP webrtc-datachannel$/D', $line) !== 1){
					throw new TransportException('invalid_sdp', 'Answer requires a data-channel media section');
				}
				if(!isset($seen['v'], $seen['o'], $seen['s'], $seen['t']) || $fingerprint === null){
					throw new TransportException('invalid_sdp', 'Answer requires session fields and a session fingerprint');
				}
				$mediaOffset ??= $offset;
			}elseif($mediaOffset === null){
				$rank = strpos('vosiuepcbtrzka', $type);
				if($rank === false || ($rank < $last && !($type === 't' && $last === 10)) ||
					(isset($seen[$type]) && str_contains('vosiuczk', $type)) || ($type === 'r' && !isset($seen['t']))){
					throw new TransportException('invalid_sdp', 'Invalid answer session field order');
				}
				if(($type === 'v' && $line !== 'v=0') ||
					($type === 'o' && preg_match('/^o=\S+ [0-9]+ [0-9]+ IN IP[46] \S+$/D', $line) !== 1) ||
					($type === 't' && preg_match('/^t=[0-9]+ [0-9]+$/D', $line) !== 1)){
					throw new TransportException('invalid_sdp', 'Invalid answer session field');
				}
				$last = $rank;
				$seen[$type] = true;
			}elseif(!str_contains('icbka', $type)){
				throw new TransportException('invalid_sdp', 'Unexpected answer media field');
			}
			if(str_starts_with($line, 'a=fingerprint:')){
				$digest = strtoupper(substr($line, strlen('a=fingerprint:sha-256 ')));
				if($fingerprint !== null && $fingerprint !== $digest){ throw new TransportException('invalid_sdp', 'Answer fingerprints name different DTLS certificates'); }
				$fingerprint = $digest;
			}
			$offset += strlen($original);
		}
		return $mediaOffset ?? throw new TransportException('invalid_sdp', 'Answer has no media section');
	}

	private function canWork(int $bytes) : bool{
		$this->syncWork();
		return $this->workMessages < $this->config->peerPollMessages && $bytes <= $this->config->peerPollBytes - $this->workBytes && $this->budget->canWork($bytes);
	}
	private function syncWork() : void{
		$generation = $this->budget->getGeneration();
		if($generation !== $this->workGeneration){
			$this->workGeneration = $generation;
			$this->workMessages = $this->workBytes = 0;
		}
	}
	private function consume(int $bytes) : void{
		$this->budget->consume($bytes);
		++$this->workMessages;
		$this->workBytes += $bytes;
	}

	private function decode(string $frame, Channel $channel, float $now) : ?string{
		$bytes = max(0, strlen($frame) - 1);
		if(!$this->budget->reserve($bytes)){ throw new TransportException('memory_limit', 'Global receive assembly budget exceeded'); }
		$this->receiveReserved += $bytes;
		$payload = $this->codec->receive($frame, $channel, $this->backend()->getMessageCapacity($channel), $now);
		$retained = $this->codec->getBufferedBytes();
		$this->budget->release($this->receiveReserved - $retained);
		$this->receiveReserved = $retained;
		return $payload;
	}

	/** @param \Closure(bool): void|null $accepted */
	public function send(string $payload, Channel $channel = Channel::RELIABLE, bool $immediate = false, ?\Closure $accepted = null) : SendResult{
		if($this->state !== ConnectionState::OPEN){
			$this->complete($accepted, false);
			return SendResult::DROPPED;
		}
		try{
			$capacity = $this->backend()->getMessageCapacity($channel);
			if($channel === Channel::UNRELIABLE){
				$frame = $this->codec->encodeUnreliable($payload, $capacity);
				$sent = false;
				if($frame !== null && $this->canWork(strlen($frame))){
					$this->consume(strlen($frame));
					$sent = $this->backend()->sendFrame($channel, $frame);
				}
			}else{
				$frames = $this->codec->encode($payload, $capacity);
			}
		}catch(\Throwable $e){
			if($e instanceof TransportException && $e->errorCode === 'payload_too_large'){
				$this->complete($accepted, false);
				return SendResult::DROPPED;
			}
			try{ $this->fail($e); }finally{ $this->complete($accepted, false); }
			return SendResult::DROPPED;
		}
		if($channel === Channel::UNRELIABLE){
			$this->complete($accepted, $sent);
			return $sent ? SendResult::ACCEPTED : SendResult::DROPPED;
		}
		$bytes = strlen($payload);
		if($bytes > $this->config->maxOutgoingQueueBytes - $this->outgoingBytes || $this->outgoing->count() >= $this->config->maxOutgoingQueueMessages || !$this->budget->reserve($bytes)){
			$this->complete($accepted, false);
			return SendResult::BACKPRESSURE;
		}
		$this->outgoingBytes += $bytes;
		$this->outgoing->enqueue(['frames' => $frames, 'bytes' => $bytes, 'complete' => $accepted]);
		if($immediate){ $this->flush(); }
		return SendResult::ACCEPTED;
	}

	private function flush() : void{
		if($this->flushing){ return; }
		$this->flushing = true;
		try{
			while($this->state === ConnectionState::OPEN && !$this->outgoing->isEmpty()){
				$entry = $this->outgoing->bottom();
				try{
					$frame = $entry['frames']->current();
					if(!$this->canWork(strlen($frame))){ break; }
					$this->consume(strlen($frame));
					if(!$this->backend()->sendFrame(Channel::RELIABLE, $frame)){ break; }
					$entry['frames']->next();
				}catch(\Throwable $e){
					unset($entry, $frame);
					$this->fail($e);
					return;
				}
				if(!$entry['frames']->valid()){
					$this->outgoing->dequeue();
					$this->outgoingBytes -= $entry['bytes'];
					$this->budget->release($entry['bytes']);
					unset($entry['frames']);
					$this->complete($entry['complete'], true);
				}
			}
		}finally{
			$this->flushing = false;
		}
	}

	private function notify(\Closure $callback) : void{
		try{ $callback(); }catch(TransportCleanupException $e){
			throw $e;
		}catch(\Throwable $e){
			$this->reportCallbackError($e);
			$this->terminate('callback_error', 'Consumer callback failed');
		}
	}

	/** @param \Closure(bool): void|null $callback */
	private function complete(?\Closure $callback, bool $success) : void{
		if($callback !== null){ $this->notify(static fn() => $callback($success)); }
	}

	private function reportCallbackError(\Throwable $error) : void{
		// never log peer data
		error_log('NetherNet consumer callback failed (' . get_class($error) . ')');
	}

	private function fail(\Throwable $error) : void{
		$code = $error instanceof TransportException ? $error->errorCode : 'backend_error';
		$this->terminate($code, $error->getMessage());
	}

	public function close(string $reason = 'local close') : void{ $this->terminate('local_close', $reason); }

	private function terminate(string $code, string $reason) : void{
		if($this->state === ConnectionState::CLOSED || $this->state === ConnectionState::CLOSING){ return; }
		$this->state = ConnectionState::CLOSING;
		$cancel = $this->cancel;
		$peer = $this->peer;
		$queue = $this->outgoing;
		$this->cancel = null;
		$this->peer = null;
		$this->offer = null;
		$this->verificationError = null;
		$this->outgoing = new \SplQueue();
		$callbacks = [];
		while(!$queue->isEmpty()){
			$entry = $queue->dequeue();
			if($entry['complete'] !== null){ $callbacks[] = $entry['complete']; }
		}
		unset($entry, $queue);
		$this->budget->release($this->outgoingBytes + $this->receiveReserved);
		$this->outgoingBytes = $this->receiveReserved = 0;
		$this->codec->reset();
		$this->state = ConnectionState::CLOSED;
		($this->closed)($this->id);
		$backendError = null;
		$callbackError = null;
		try{ if($cancel !== null){ $cancel(); } }
		catch(TransportCleanupException $e){ $backendError = $e; }
		catch(\Throwable $e){ $callbackError = $e; $this->reportCallbackError($e); }
		try{ if($peer !== null){ $peer->close(); } }catch(\Throwable $e){ $backendError = $e; }
		foreach($callbacks as $callback){
			try{ $callback(false); }
			catch(TransportCleanupException $e){ $backendError ??= $e; }
			catch(\Throwable $e){ $callbackError ??= $e; $this->reportCallbackError($e); }
		}
		if($code === 'local_close' && $callbackError !== null){ $code = 'callback_error'; $reason = 'Consumer callback failed during close'; }
		try{ $this->listener->onClose($this->id, $code, $reason); }
		catch(TransportCleanupException $e){ $backendError ??= $e; }
		catch(\Throwable $e){ $this->reportCallbackError($e); }
		if($backendError !== null){ throw $backendError instanceof TransportCleanupException ? $backendError : new TransportCleanupException($backendError); }
	}
}
