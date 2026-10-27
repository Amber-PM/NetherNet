<?php

declare(strict_types=1);

namespace amber\nethernet\signaling;

use amber\nethernet\TransportConfig;
use amber\nethernet\SignalingPeerAddress;

final class HttpServer{
	/** @var resource|null */
	private mixed $listener = null;
	/** @var array<int, HttpSocket> */
	private array $clients = [];
	/** @var array<string, int> */
	private array $connectionsByIp = [];
	private bool $polling = false;
	private bool $stopped = false;
	private readonly string $address;
	/** @var \Closure(): float */
	private readonly \Closure $clock;
	private float $lastNow = 0.0;
	/** @var int<1, 1048576> */
	private readonly int $ioBytes;

	/**
	 * @param \Closure(): float|null $clock
	 * @param \Closure(string): bool|null $admit
	 */
	public function __construct(
		private readonly TransportConfig $config,
		private readonly HttpSignaling $signaling,
		string $bind = 'tcp://127.0.0.1:0',
		int $ioBytes = 16384,
		?\Closure $clock = null,
		private readonly ?\Closure $admit = null
	){
		if($ioBytes < 1 || $ioBytes > 1048576 || preg_match('~^tcp://([0-9.]+|\[[0-9a-fA-F:.]+\]):([0-9]{1,5})$~D', $bind, $parts) !== 1 ||
			filter_var(trim($parts[1], '[]'), FILTER_VALIDATE_IP, $parts[1][0] === '[' ? FILTER_FLAG_IPV6 : FILTER_FLAG_IPV4) === false || (int) $parts[2] > 65535){
			throw new \InvalidArgumentException('HTTP requires a numeric TCP bind and an I/O budget of 1..1048576 bytes');
		}
		$this->ioBytes = $ioBytes;
		$this->clock = $clock ?? static fn() => hrtime(true) / 1_000_000_000;
		$this->now();
		$stream = @stream_socket_server($bind, $code, $error, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
		if($stream === false){ throw new \RuntimeException('HTTP listener bind failed (' . $code . ')'); }
		try{
			if(!stream_set_blocking($stream, false)){ throw new \RuntimeException('HTTP listener could not become nonblocking'); }
			$address = stream_socket_get_name($stream, false);
			if($address === false){ throw new \RuntimeException('HTTP listener address unavailable'); }
			$this->address = $address;
			$this->listener = $stream;
		}catch(\Throwable $e){
			fclose($stream);
			throw $e;
		}
	}

	private function __clone(){}

	private function now() : float{
		$now = ($this->clock)();
		if(!is_finite($now) || $now < $this->lastNow){ throw new \InvalidArgumentException('HTTP clock must be finite, nonnegative and monotonic'); }
		return $this->lastNow = $now;
	}

	public function getAddress() : string{ return $this->address; }
	public function getConnectionCount() : int{ return count($this->clients); }
	public function getBufferedBytes() : int{
		$bytes = 0;
		foreach($this->clients as $client){ $bytes += strlen($client->output); }
		return $bytes;
	}

	public function poll(int $waitMicroseconds = 0) : void{
		if($waitMicroseconds < 0 || $waitMicroseconds > 10000){ throw new \InvalidArgumentException('HTTP poll wait must be within 0..10000 microseconds'); }
		if($this->polling){ throw new \LogicException('HTTP polling cannot be reentered'); }
		if($this->stopped){ return; }
		$this->polling = true;
		try{
			$this->pollSockets($waitMicroseconds);
		}catch(\Throwable $e){
			try{ $this->stop(); }finally{ throw $e; }
		}finally{
			$this->polling = false;
		}
	}

	private function pollSockets(int $waitMicroseconds) : void{
		$now = $this->now();
		foreach($this->clients as $id => $client){ $this->prepare($id, $client, $now); }
		if($this->stopped || $this->listener === null){ return; }
		$read = [$this->listener];
		$write = [];
		foreach($this->clients as $client){
			if($client->reading){ $read[] = $client->stream; }
			if($client->output !== ''){ $write[] = $client->stream; }
			$waitMicroseconds = min($waitMicroseconds, max(0, (int) (($client->deadline - $now) * 1_000_000)));
		}
		$except = null;
		$selected = @stream_select($read, $write, $except, 0, $waitMicroseconds);
		if($selected === false){ throw new \RuntimeException('HTTP socket selection failed'); }
		if(in_array($this->listener, $read, true)){ $this->accept(); }
		foreach($this->clients as $id => $client){
			if($this->stopped){ break; }
			$this->prepare($id, $client, $this->now());
			if(!isset($this->clients[$id])){ continue; }
			if($client->reading && in_array($client->stream, $read, true)){
				$bytes = @fread($client->stream, $this->ioBytes);
				if($bytes === false){ $this->drop($id); continue; }
				if($bytes !== ''){ $this->signaling->receive($id, $bytes); }
				elseif(feof($client->stream)){
					$client->reading = false;
					$this->signaling->eof($id);
				}
			}
			if($this->stopped){ continue; }
			$this->prepare($id, $client, $this->now());
			if(isset($this->clients[$id]) && in_array($client->stream, $write, true)){ $this->write($id, $client); }
		}
	}

	private function accept() : void{
		for($i = 0; $i < 16 && !$this->stopped && $this->listener !== null; ++$i){
			$stream = @stream_socket_accept($this->listener, 0);
			if($stream === false){ break; }
			if(count($this->clients) >= $this->config->maxHttpConnections){ fclose($stream); continue; }
			try{
				if(!stream_set_blocking($stream, false)){
					throw new \RuntimeException('HTTP client could not become nonblocking');
				}
				$peerName = stream_socket_get_name($stream, true);
				if($peerName === false){ fclose($stream); continue; }
				try{ $peerAddress = SignalingPeerAddress::fromSocketName($peerName); }
				catch(\InvalidArgumentException){ fclose($stream); continue; }
				// one address must not hold every slot and banned peers stop before parsing
				if(($this->connectionsByIp[$peerAddress->ip] ?? 0) >= $this->config->maxHttpConnectionsPerIp || ($this->admit !== null && !($this->admit)($peerAddress->ip))){ fclose($stream); continue; }
				$id = $this->signaling->open($peerAddress);
			}catch(HttpException){
				fclose($stream);
				continue;
			}catch(\Throwable $e){
				fclose($stream);
				throw $e;
			}
			$this->clients[$id] = new HttpSocket($stream, $peerAddress->ip, $this->now() + $this->config->httpHeaderTimeoutSeconds);
			$this->connectionsByIp[$peerAddress->ip] = ($this->connectionsByIp[$peerAddress->ip] ?? 0) + 1;
		}
	}

	private function prepare(int $id, HttpSocket $client, float $now) : void{
		if(!isset($this->clients[$id])){ return; }
		$state = $this->signaling->getState($id);
		if($state === HttpState::CLOSED){ $this->drop($id); return; }
		if($state !== $client->state){
			$client->state = $state;
			$client->deadline = $now + $this->config->signalingTimeoutSeconds;
		}
		if($now >= $client->deadline){
			if($state === HttpState::HEADERS || $state === HttpState::BODY){ $client->reading = false; }
			$this->signaling->timeout($id);
			if($this->stopped || $this->signaling->getState($id) === HttpState::CLOSED){ $this->drop($id); return; }
		}
		$response = $this->signaling->takeResponse($id);
		if($response !== null){
			if(strlen($response->body) > max($this->config->maxSdpBytes, 32768)){
				throw new \RuntimeException('HTTP response exceeds bounded profile');
			}
			$client->output = $response->encode();
			$client->state = HttpState::WRITING;
			$client->deadline = $now + $this->config->signalingTimeoutSeconds;
		}
	}

	private function write(int $id, HttpSocket $client) : void{
		if($this->signaling->getState($id) === HttpState::CLOSED){ $this->drop($id); return; }
		$written = @fwrite($client->stream, substr($client->output, $client->offset, $this->ioBytes));
		if($written === false){ $this->drop($id); return; }
		$client->offset += $written;
		if($client->offset === strlen($client->output)){
			$this->signaling->finish($id);
			$this->drop($id);
		}
	}

	private function drop(int $id) : void{
		$client = $this->clients[$id] ?? null;
		if($client === null){ return; }
		unset($this->clients[$id]);
		if(--$this->connectionsByIp[$client->ip] === 0){ unset($this->connectionsByIp[$client->ip]); }
		$client->output = '';
		fclose($client->stream);
		$this->signaling->cancel($id);
	}

	public function stop() : void{
		if($this->stopped){ return; }
		$this->stopped = true;
		if($this->listener !== null){ fclose($this->listener); $this->listener = null; }
		$error = null;
		foreach(array_keys($this->clients) as $id){
			try{ $this->drop($id); }catch(\Throwable $e){ $error ??= $e; }
		}
		try{ $this->signaling->stop(); }catch(\Throwable $e){ $error ??= $e; }
		if($error !== null){ throw $error; }
	}

	public function __destruct(){ $this->stop(); }
}
