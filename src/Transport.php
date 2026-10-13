<?php

declare(strict_types=1);

namespace amber\nethernet;

use amber\nethernet\backend\ExtWebRtcPeer;
use amber\nethernet\backend\WebRtcPeer;
use amber\nethernet\identity\IdentityHandler;
use amber\nethernet\identity\SdpIdentity;
use amber\nethernet\internal\TransportBudget;

final class Transport{
	/** @var array<int, PeerConnection> */
	private array $connections = [];
	private int $nextId = 1;
	private int $cursor = 0;
	private bool $polling = false;
	private bool $stopped = false;
	private float $lastNow = 0.0;
	private readonly TransportBudget $budget;
	/** @var \Closure(): WebRtcPeer */
	private readonly \Closure $factory;
	/** @var \Closure(): float */
	private readonly \Closure $clock;
	/** @var \Closure(): int */
	private readonly \Closure $wallClock;

	/**
	 * @param \Closure(): WebRtcPeer|null $factory
	 * @param \Closure(): float|null $clock
	 * @param \Closure(): int|null $wallClock
	 */
	public function __construct(
		private readonly TransportConfig $config,
		private readonly IdentityHandler $identityHandler,
		private readonly TransportListener $listener,
		?\Closure $factory = null,
		?\Closure $clock = null,
		?\Closure $wallClock = null
	){
		if($config->maxMessageBytes > min($config->peerPollBytes, $config->globalPollBytes)){
			throw new \InvalidArgumentException('Poll byte budgets must hold one maximum-size frame');
		}
		$this->factory = $factory ?? static fn() => new ExtWebRtcPeer($config);
		$this->clock = $clock ?? static fn() => hrtime(true) / 1_000_000_000;
		$this->wallClock = $wallClock ?? static fn() => time();
		$this->budget = new TransportBudget($config);
	}

	private function now() : float{
		$now = ($this->clock)();
		if(!is_finite($now) || $now < $this->lastNow){
			throw new \InvalidArgumentException('Transport clock must be finite, nonnegative and monotonic');
		}
		return $this->lastNow = $now;
	}

	public function accept(string $networkId, string $offerSdp) : int{
		if($this->stopped){ throw new TransportException('closed', 'Transport is stopped'); }
		if($networkId === '' || strlen($networkId) > $this->config->maxNetworkIdBytes){
			throw new TransportException('network_id_invalid', 'Network ID is empty or exceeds limit');
		}
		$pending = 0;
		foreach($this->connections as $connection){
			if($connection->getState() !== ConnectionState::OPEN){ ++$pending; }
		}
		if(count($this->connections) >= $this->config->maxConnections || $pending >= $this->config->maxPendingNegotiations){
			throw new TransportException('connection_limit', 'Connection or negotiation limit reached');
		}
		if($this->nextId === PHP_INT_MAX){ throw new TransportException('connection_limit', 'Connection IDs exhausted'); }
		$identity = SdpIdentity::fromSdp($offerSdp, $this->config);
		if($identity->token === null || $identity->detachedJws === null){
			throw new TransportException('identity_missing', 'Client identity is required');
		}
		$id = $this->nextId++;
		$owner = \WeakReference::create($this);
		$connection = new PeerConnection($id, $networkId, $identity, $this->config, $this->identityHandler, $this->listener, $this->factory, $this->wallClock, $this->budget, $this->now(), static function(int $closedId) use ($owner) : void{
			$transport = $owner->get();
			if($transport !== null){ unset($transport->connections[$closedId]); }
		});
		$this->connections[$id] = $connection;
		$connection->startVerification();
		return $id;
	}

	public function poll() : void{
		if($this->polling){ throw new \LogicException('Transport polling cannot be reentered'); }
		if($this->stopped){ return; }
		$now = $this->now();
		$this->polling = true;
		try{
			$this->budget->resetWork();
			$ids = array_keys($this->connections);
			$count = count($ids);
			if($count === 0){ return; }
			$start = $this->cursor % $count;
			$this->cursor = ($start + 1) % $count;
			$this->pollConnections($ids, $start, $now);
		}finally{
			$this->polling = false;
		}
	}

	/** @param list<int> $ids */
	private function pollConnections(array $ids, int $start, float $now) : void{
		$count = count($ids);
		for($offset = 0; $offset < $count && !$this->stopped; ++$offset){
			($this->connections[$ids[($start + $offset) % $count]] ?? null)?->poll($now);
		}
	}

	public function close(int $id, string $reason = 'local close') : void{
		if(isset($this->connections[$id])){ $this->connections[$id]->close($reason); }
	}

	public function stop() : void{
		if($this->stopped){ return; }
		$this->stopped = true;
		$error = null;
		foreach($this->connections as $connection){
			try{ $connection->close('transport stopped'); }catch(\Throwable $e){ $error ??= $e; }
		}
		$this->connections = [];
		if($error !== null){ throw $error; }
	}

	public function __destruct(){ $this->stop(); }
}
