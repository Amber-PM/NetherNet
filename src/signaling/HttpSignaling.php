<?php

declare(strict_types=1);

namespace amber\nethernet\signaling;

use amber\nethernet\Channel;
use amber\nethernet\Connection;
use amber\nethernet\Transport;
use amber\nethernet\TransportConfig;
use amber\nethernet\TransportException;
use amber\nethernet\TransportListener;

final class HttpSignaling implements TransportListener{
	/** @var array<int, HttpExchange> */
	private array $exchanges = [];
	/** @var array<int, int> */
	private array $byTransport = [];
	/** @var \WeakReference<Transport>|null */
	private ?\WeakReference $transport = null;
	private int $nextId = 1;
	private bool $stopped = false;
	private bool $admitting = false;

	/** @param \Closure(): ServerMetadata $metadata */
	public function __construct(
		private readonly TransportConfig $config,
		private readonly \Closure $metadata,
		private readonly TransportListener $listener
	){}

	public function bind(Transport $transport) : void{
		if($this->transport !== null || $this->stopped){ throw new \LogicException('HTTP signaling can be bound only once'); }
		$this->transport = \WeakReference::create($transport);
	}

	private function transport() : Transport{
		return $this->transport?->get() ?? throw new \LogicException('HTTP signaling requires a live bound transport');
	}

	public function open() : int{
		$this->transport();
		if($this->stopped || count($this->exchanges) >= $this->config->maxHttpConnections || $this->nextId === PHP_INT_MAX){ throw new HttpException(503); }
		$id = $this->nextId++;
		$this->exchanges[$id] = new HttpExchange(new HttpRequestParser($this->config));
		return $id;
	}

	public function getState(int $id) : HttpState{ return $this->exchanges[$id]->state ?? HttpState::CLOSED; }
	public function getTransportId(int $id) : ?int{ return $this->exchanges[$id]->transportId ?? null; }

	public function receive(int $id, string $bytes) : void{
		$exchange = $this->exchanges[$id] ?? null;
		if($exchange === null || $bytes === ''){ return; }
		if($this->admitting){ throw new \LogicException('HTTP transport admission cannot be reentered'); }
		if($exchange->dispatching){ throw new \LogicException('HTTP request dispatch cannot be reentered'); }
		if($exchange->state === HttpState::WRITING){ $this->cancel($id); return; }
		if($exchange->parser === null){ $this->reject($id, new HttpException(400)); return; }
		$exchange->parser->feed($bytes);
		$this->dispatch($id, $exchange);
	}

	public function eof(int $id) : void{
		$exchange = $this->exchanges[$id] ?? null;
		if($exchange?->parser !== null){
			$exchange->parser->eof();
			$this->dispatch($id, $exchange);
		}
	}

	private function dispatch(int $id, HttpExchange $exchange) : void{
		$parser = $exchange->parser ?? throw new \LogicException('Request parser was released');
		if(($error = $parser->getError()) !== null){ $this->reject($id, $error); return; }
		$request = $parser->takeRequest();
		if($request === null){
			$exchange->state = $parser->getState() === HttpParseState::BODY ? HttpState::BODY : HttpState::HEADERS;
			return;
		}
		$exchange->parser = null;
		$exchange->dispatching = true;
		try{
			if($request['networkId'] === null){
				$state = $this->getState($id);
				try{ $response = new HttpResponse(200, ($this->metadata)()->toJson(), 'application/json'); }
				catch(\Throwable){ $response = HttpResponse::error(500); }
				if(($this->exchanges[$id] ?? null) === $exchange && $this->getState($id) === $state){ $this->respond($exchange, $response); }
				return;
			}
			$exchange->state = HttpState::PENDING;
			if($this->admitting){ throw new \LogicException('HTTP transport admission cannot be reentered'); }
			$this->admitting = true;
			try{
				$transportId = $this->transport()->accept($request['networkId'], $request['body']);
			}catch(TransportException $e){
				$this->reject($id, new HttpException(self::failureStatus($e->errorCode, true)));
				return;
			}catch(\Throwable){
				$this->reject($id, new HttpException(500));
				return;
			}finally{
				$this->admitting = false;
			}
			if(($this->exchanges[$id] ?? null) !== $exchange || $this->getState($id) !== HttpState::PENDING){
				$this->transport()->close($transportId, 'HTTP signaling cancelled during admission');
				return;
			}
			$exchange->transportId = $transportId;
			$this->byTransport[$transportId] = $id;
		}finally{
			$exchange->dispatching = false;
		}
	}

	private static function failureStatus(string $code, bool $admission = false) : int{
		return match($code){
			'connection_limit', 'closed' => 503,
			'signaling_timeout' => 504,
			'identity_missing', 'identity_invalid', 'identity_signature_invalid', 'identity_untrusted',
			'identity_claims_invalid', 'identity_expired', 'identity_key_invalid', 'identity_fingerprint_mismatch' => 403,
			'invalid_sdp', 'network_id_invalid' => $admission ? 400 : 500,
			default => 500
		};
	}

	private function respond(HttpExchange $exchange, HttpResponse $response) : void{
		$exchange->parser = null;
		$exchange->response = $response;
		$exchange->state = HttpState::RESPONSE;
	}

	private function reject(int $id, HttpException $error) : void{
		$exchange = $this->exchanges[$id] ?? null;
		if($exchange === null){ return; }
		if($exchange->state === HttpState::WRITING){ $this->cancel($id); return; }
		$this->respond($exchange, HttpResponse::error($error->status, $error->allow));
		$this->detachPeer($exchange, true);
	}

	public function timeout(int $id) : void{
		$state = $this->getState($id);
		if($state === HttpState::HEADERS || $state === HttpState::BODY){ $this->reject($id, new HttpException(408)); }
		elseif($state === HttpState::PENDING){ $this->reject($id, new HttpException(504)); }
		else{ $this->cancel($id); }
	}

	public function takeResponse(int $id) : ?HttpResponse{
		$exchange = $this->exchanges[$id] ?? null;
		if($exchange === null || $exchange->state !== HttpState::RESPONSE){ return null; }
		$response = $exchange->response;
		$exchange->response = null;
		$exchange->state = HttpState::WRITING;
		return $response;
	}

	public function finish(int $id) : void{
		$exchange = $this->exchanges[$id] ?? null;
		if($exchange === null){ return; }
		if($exchange->state !== HttpState::WRITING){ throw new \LogicException('HTTP response must be taken and fully delivered before finish'); }
		unset($this->exchanges[$id]);
		$this->detachPeer($exchange, false);
	}

	public function cancel(int $id) : void{
		$exchange = $this->exchanges[$id] ?? null;
		if($exchange === null){ return; }
		unset($this->exchanges[$id]);
		$exchange->parser = null;
		$exchange->response = null;
		$this->detachPeer($exchange, true);
	}

	private function detachPeer(HttpExchange $exchange, bool $cancel) : void{
		$id = $exchange->transportId;
		if($id === null){ return; }
		unset($this->byTransport[$id]);
		$exchange->transportId = null;
		if($cancel && !$exchange->opened){ $this->transport?->get()?->close($id, 'HTTP signaling cancelled'); }
	}

	public function stop() : void{
		if($this->stopped){ return; }
		$this->stopped = true;
		$error = null;
		foreach(array_keys($this->exchanges) as $id){
			try{ $this->cancel($id); }catch(\Throwable $e){ $error ??= $e; }
		}
		if($error !== null){ throw $error; }
	}

	public function onAnswer(int $id, string $answerSdp) : void{
		if($this->admitting){ throw new \LogicException('Transport cannot emit answers during HTTP admission'); }
		$exchangeId = $this->byTransport[$id] ?? null;
		$exchange = $exchangeId !== null ? ($this->exchanges[$exchangeId] ?? null) : null;
		if($exchange === null || $exchange->state !== HttpState::PENDING){ return; }
		$this->respond($exchange, new HttpResponse(200, $answerSdp, 'application/sdp'));
		$this->listener->onAnswer($id, $answerSdp);
	}

	public function onOpen(Connection $connection) : void{
		$exchangeId = $this->byTransport[$connection->getId()] ?? null;
		if($exchangeId !== null && isset($this->exchanges[$exchangeId])){ $this->exchanges[$exchangeId]->opened = true; }
		$this->listener->onOpen($connection);
	}

	public function onPayload(Connection $connection, string $payload, Channel $channel) : void{ $this->listener->onPayload($connection, $payload, $channel); }

	public function onClose(int $id, string $code, string $reason) : void{
		$exchangeId = $this->byTransport[$id] ?? null;
		unset($this->byTransport[$id]);
		$exchange = $exchangeId !== null ? ($this->exchanges[$exchangeId] ?? null) : null;
		if($exchange !== null){
			$exchange->transportId = null;
			if($exchange->state === HttpState::PENDING || $exchange->state === HttpState::RESPONSE){
				$this->respond($exchange, HttpResponse::error(self::failureStatus($code)));
			}elseif($exchange->state === HttpState::WRITING){
				unset($this->exchanges[$exchangeId]);
			}
		}
		$this->listener->onClose($id, $code, $reason);
	}
}
