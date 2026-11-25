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
	/** @var array<int, array{stream: resource, deadline: float, address: SignalingPeerAddress}> */
	private array $proxied = [];
	private int $nextProxied = 0;
	/** @var array{https: int, http: int, tlsRefused: int, tlsFailed: int} */
	private array $schemes = ['https' => 0, 'http' => 0, 'tlsRefused' => 0, 'tlsFailed' => 0];
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
	 * @param list<string> $trustedProxies
	 */
	public function __construct(
		private readonly TransportConfig $config,
		private readonly HttpSignaling $signaling,
		string $bind = 'tcp://127.0.0.1:0',
		int $ioBytes = 16384,
		?\Closure $clock = null,
		private readonly ?\Closure $admit = null,
		private readonly array $trustedProxies = [],
		private readonly ?TlsConfig $tls = null
	){
		ProxyProtocol::assertNetworks($trustedProxies);
		if($ioBytes < 1 || $ioBytes > 1048576 || preg_match('~^tcp://([0-9.]+|\[[0-9a-fA-F:.]+\]):([0-9]{1,5})$~D', $bind, $parts) !== 1 ||
			filter_var(trim($parts[1], '[]'), FILTER_VALIDATE_IP, $parts[1][0] === '[' ? FILTER_FLAG_IPV6 : FILTER_FLAG_IPV4) === false || (int) $parts[2] > 65535){
			throw new \InvalidArgumentException('HTTP requires a numeric TCP bind and an I/O budget of 1..1048576 bytes');
		}
		$this->ioBytes = $ioBytes;
		$this->clock = $clock ?? static fn() => hrtime(true) / 1_000_000_000;
		$this->now();
		// accepted sockets inherit the tls options, the handshake starts only when a client opens with one
		$stream = @stream_socket_server($bind, $code, $error, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, stream_context_create($tls !== null ? ['ssl' => $tls->contextOptions()] : []));
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
	/** @return array{https: int, http: int, tlsRefused: int, tlsFailed: int} */
	public function getSchemeCounts() : array{ return $this->schemes; }
	public function getConnectionCount() : int{ return count($this->clients) + count($this->proxied); }
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
		foreach($this->proxied as $entry){
			$read[] = $entry['stream'];
			$waitMicroseconds = min($waitMicroseconds, max(0, (int) (($entry['deadline'] - $now) * 1_000_000)));
		}
		foreach($this->clients as $client){
			if($client->reading){ $read[] = $client->stream; }
			if($client->output !== ''){ $write[] = $client->stream; }
			$waitMicroseconds = min($waitMicroseconds, max(0, (int) (($client->deadline - $now) * 1_000_000)));
		}
		$except = null;
		// select fails for descriptors above FD_SETSIZE, the sockets are nonblocking so try them all
		$blind = @stream_select($read, $write, $except, 0, $waitMicroseconds) === false;
		if($blind && $waitMicroseconds > 0){ usleep($waitMicroseconds); }
		if($blind || in_array($this->listener, $read, true)){ $this->accept(); }
		foreach($this->proxied as $key => $entry){
			if($this->stopped){ break; }
			if($blind || in_array($entry['stream'], $read, true) || $this->now() >= $entry['deadline']){ $this->readProxyHeader($key); }
		}
		foreach($this->clients as $id => $client){
			if($this->stopped){ break; }
			$this->prepare($id, $client, $this->now());
			if(!isset($this->clients[$id])){ continue; }
			if($client->tls === null && !$this->secure($id, $client)){ continue; }
			// openssl may hold decrypted bytes that select cannot see
			if($client->reading && ($blind || $client->tls === true || in_array($client->stream, $read, true))){
				$bytes = @fread($client->stream, $this->ioBytes);
				if($bytes === false){ $this->drop($id); continue; }
				if($bytes !== '' && !$client->counted){
					$client->counted = true;
					// clients try tls first and fall back, so a refused hello is normal without a certificate
					++$this->schemes[$client->tls === true ? 'https' : ($bytes[0] === "\x16" ? 'tlsRefused' : 'http')];
				}
				if($bytes !== ''){ $this->signaling->receive($id, $bytes); }
				elseif(feof($client->stream)){
					$client->reading = false;
					$this->signaling->eof($id);
				}
			}
			if($this->stopped){ continue; }
			$this->prepare($id, $client, $this->now());
			if(isset($this->clients[$id]) && ($blind || $client->tls === true ? $client->output !== '' : in_array($client->stream, $write, true))){ $this->write($id, $client); }
		}
	}

	private function accept() : void{
		for($i = 0; $i < 16 && !$this->stopped && $this->listener !== null; ++$i){
			$stream = @stream_socket_accept($this->listener, 0);
			if($stream === false){ break; }
			if(count($this->clients) + count($this->proxied) >= $this->config->maxHttpConnections){ fclose($stream); continue; }
			try{
				if(!stream_set_blocking($stream, false)){
					throw new \RuntimeException('HTTP client could not become nonblocking');
				}
				$peerName = stream_socket_get_name($stream, true);
				if($peerName === false){ fclose($stream); continue; }
				try{ $peerAddress = SignalingPeerAddress::fromSocketName($peerName); }
				catch(\InvalidArgumentException){ fclose($stream); continue; }
				// a trusted proxy names the real player address first
				if(ProxyProtocol::matches($peerAddress->ip, $this->trustedProxies)){
					$this->proxied[$this->nextProxied++] = ['stream' => $stream, 'deadline' => $this->now() + $this->config->httpHeaderTimeoutSeconds, 'address' => $peerAddress];
					continue;
				}
			}catch(\Throwable $e){
				fclose($stream);
				throw $e;
			}
			$this->admitClient($stream, $peerAddress, $this->now() + $this->config->httpHeaderTimeoutSeconds);
		}
	}

	/** @param resource $stream */
	private function admitClient(mixed $stream, SignalingPeerAddress $peerAddress, float $deadline) : void{
		try{
			// one address must not hold every slot and banned peers stop before parsing
			if(($this->connectionsByIp[$peerAddress->ip] ?? 0) >= $this->config->maxHttpConnectionsPerIp || ($this->admit !== null && !($this->admit)($peerAddress->ip))){ $this->reject($stream); return; }
			$id = $this->signaling->open($peerAddress);
		}catch(HttpException){
			$this->reject($stream);
			return;
		}catch(\Throwable $e){
			$this->reject($stream);
			throw $e;
		}
		$client = new HttpSocket($stream, $peerAddress->ip, $deadline);
		if($this->tls !== null){ $client->tls = null; }
		$this->clients[$id] = $client;
		$this->connectionsByIp[$peerAddress->ip] = ($this->connectionsByIp[$peerAddress->ip] ?? 0) + 1;
	}

	private function secure(int $id, HttpSocket $client) : bool{
		if($this->tls === null){ return true; }
		// timed out before the handshake finished, no channel exists to answer on
		if(!$client->reading){ $this->drop($id); return false; }
		if(!$client->handshaking){
			// a tls record starts with 0x16, http starts with a letter
			$first = @stream_socket_recvfrom($client->stream, 1, STREAM_PEEK);
			if($first === false){ return false; }
			if($first === '' || ($first !== "\x16" && $this->tls->required)){
				// unread bytes would turn the close into a reset
				@stream_socket_recvfrom($client->stream, 65536);
				$this->drop($id);
				return false;
			}
			if($first !== "\x16"){
				$client->tls = false;
				return true;
			}
			$client->handshaking = true;
		}
		$result = @stream_socket_enable_crypto($client->stream, true, TlsConfig::method());
		if($result === false){
			$this->drop($id);
			return false;
		}
		if($result !== true){ return false; }
		$client->handshaking = false;
		$client->tls = true;
		return true;
	}

	private function readProxyHeader(int $key) : void{
		$entry = $this->proxied[$key];
		// peek so nothing after the header leaves the socket, a tls handshake may follow
		$bytes = @stream_socket_recvfrom($entry['stream'], ProxyProtocol::MAX_BYTES, STREAM_PEEK);
		try{
			if($bytes === '' || $this->now() >= $entry['deadline']){ throw new \InvalidArgumentException('PROXY header never arrived'); }
			if($bytes === false){ return; }
			$header = ProxyProtocol::parse($bytes);
			if($header === null){
				if(strlen($bytes) >= ProxyProtocol::MAX_BYTES){ throw new \InvalidArgumentException('PROXY header exceeds limit'); }
				return;
			}
			if(strlen((string) @stream_socket_recvfrom($entry['stream'], $header[1])) !== $header[1]){ throw new \InvalidArgumentException('PROXY header could not be consumed'); }
		}catch(\InvalidArgumentException){
			unset($this->proxied[$key]);
			$this->reject($entry['stream']);
			return;
		}
		unset($this->proxied[$key]);
		$this->admitClient($entry['stream'], $header[0] ?? $entry['address'], $entry['deadline']);
	}

	/** @param resource $stream */
	private function reject(mixed $stream) : void{
		// unread bytes would turn the close into a reset
		@stream_socket_recvfrom($stream, 65536);
		fclose($stream);
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
		// clients that dislike the certificate often abandon the hello and retry over http
		// or finish the handshake, check the certificate afterwards and leave without a request
		if($client->handshaking || ($client->tls === true && !$client->counted)){ ++$this->schemes['tlsFailed']; }
		if(--$this->connectionsByIp[$client->ip] === 0){ unset($this->connectionsByIp[$client->ip]); }
		$client->output = '';
		fclose($client->stream);
		$this->signaling->cancel($id);
	}

	public function stop() : void{
		if($this->stopped){ return; }
		$this->stopped = true;
		if($this->listener !== null){ fclose($this->listener); $this->listener = null; }
		foreach($this->proxied as $entry){ fclose($entry['stream']); }
		$this->proxied = [];
		$error = null;
		foreach(array_keys($this->clients) as $id){
			try{ $this->drop($id); }catch(\Throwable $e){ $error ??= $e; }
		}
		try{ $this->signaling->stop(); }catch(\Throwable $e){ $error ??= $e; }
		if($error !== null){ throw $error; }
	}

	public function __destruct(){ $this->stop(); }
}
