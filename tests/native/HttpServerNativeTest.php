<?php

declare(strict_types=1);

namespace amber\nethernet\tests\native;

use amber\nethernet\backend\ExtWebRtcPeer;
use amber\nethernet\Channel;
use amber\nethernet\ConnectionState;
use amber\nethernet\framing\FrameCodec;
use amber\nethernet\identity\ClientServerIdentityHandler;
use amber\nethernet\identity\SdpIdentity;
use amber\nethernet\SendResult;
use amber\nethernet\SignalingPeerConnection;
use amber\nethernet\signaling\HttpServer;
use amber\nethernet\signaling\HttpSignaling;
use amber\nethernet\signaling\HttpState;
use amber\nethernet\signaling\ServerMetadata;
use amber\nethernet\tests\identity\IdentityFixture;
use amber\nethernet\tests\signaling\AnswerSignatures;
use amber\nethernet\tests\transport\RecordingListener;
use amber\nethernet\Transport;
use amber\nethernet\TransportConfig;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use pmmp\webrtc\DataChannel;
use pmmp\webrtc\DataChannelOptions;
use pmmp\webrtc\GatheringState;
use pmmp\webrtc\PeerConnection;
use pmmp\webrtc\PeerConnectionOptions;

final class HttpServerNativeTest extends TestCase{
	private TransportConfig $config;
	private IdentityFixture $fixture;
	private RecordingListener $listener;
	private HttpSignaling $http;
	private HttpServer $host;
	private Transport $transport;
	private PeerConnection $client;
	/** @var array<string, DataChannel> */
	private array $channels = [];
	/** @var list<ExtWebRtcPeer> */
	private array $peers = [];
	/** @var list<resource> */
	private array $sockets = [];
	/** @var array<string, int|float|string> */
	private array $evidence = [];
	private float $clockOffset = 0.0;

	protected function setUp() : void{
		ExtWebRtcPeer::assertAvailable();
		$this->config = new TransportConfig(maxMessageBytes: 512, maxPayloadBytes: 4096);
		$this->fixture = new IdentityFixture();
		$this->listener = new RecordingListener();
		$this->listener->answered = function() : void{ $this->evidence['answer_created_ns'] = hrtime(true); };
		$this->http = new HttpSignaling($this->config, static fn() => new ServerMetadata('Native TCP', 1, 'fixture', 'World', 0, 2, 0), $this->listener);
		$clock = fn() => hrtime(true) / 1_000_000_000 + $this->clockOffset;
		$this->transport = new Transport($this->config, new ClientServerIdentityHandler($this->fixture->verifier(), $this->fixture->server, $this->config), $this->http, function() : ExtWebRtcPeer{
			$peer = new ExtWebRtcPeer($this->config);
			$this->peers[] = $peer;
			$this->evidence['backend_created_ns'] = hrtime(true);
			return $peer;
		}, $clock);
		$this->http->bind($this->transport);
		$this->host = new HttpServer($this->config, $this->http, ioBytes: 257, clock: $clock);
		$this->client = new PeerConnection(PeerConnectionOptions::create()->setMaxMessageSize(512)->setIceTcpEnabled(false));
		$this->evidence['started_ns'] = hrtime(true);
	}

	protected function tearDown() : void{
		$started = hrtime(true);
		try{
			if(isset($this->host)){ $this->host->stop(); }
		}finally{
			try{
				if(isset($this->transport)){ $this->transport->stop(); }
			}finally{
				foreach($this->channels as $channel){ $channel->close(); }
				if(isset($this->client)){ $this->client->close(); }
				foreach($this->sockets as $socket){ if(is_resource($socket)){ fclose($socket); } }
			}
		}
		foreach($this->peers as $peer){ self::assertSame('CLOSED', $peer->getState()); }
		$references = array_map(static fn(ExtWebRtcPeer $peer) => \WeakReference::create($peer), $this->peers);
		if(isset($this->transport)){ $references[] = \WeakReference::create($this->transport); }
		if(isset($this->host)){ $references[] = \WeakReference::create($this->host); }
		if(isset($this->http)){ $references[] = \WeakReference::create($this->http); }
		if(isset($this->client)){ $references[] = \WeakReference::create($this->client); }
		if(isset($this->listener)){
			foreach($this->listener->connections as $connection){ $references[] = \WeakReference::create($connection); }
		}
		unset($peer, $channel, $connection, $this->transport, $this->host, $this->http, $this->client, $this->listener);
		$this->peers = [];
		$this->channels = [];
		$this->sockets = [];
		gc_collect_cycles();
		foreach($references as $reference){ self::assertNull($reference->get()); }
		$this->evidence['released_php_owners'] = count($references);
		$this->evidence['cleanup_ms'] = (hrtime(true) - $started) / 1_000_000;
		$this->evidence['closed_ns'] = hrtime(true);
		$path = getenv('NETHERNET_GATE_B_EVIDENCE');
		if($path !== false && $path !== ''){
			self::assertNotFalse(file_put_contents($path, json_encode(['test' => $this->nameWithDataSet()] + $this->evidence, JSON_THROW_ON_ERROR) . "\n", FILE_APPEND | LOCK_EX));
		}
	}

	private function tick(bool $advanceTransport = true) : void{
		$started = hrtime(true);
		if($advanceTransport){ $this->transport->poll(); }
		$this->host->poll(1000);
		self::assertSame([], $this->client->pollDataChannels());
		if($this->client->getState()->name === 'CONNECTED' && !isset($this->evidence['native_connected_ns'])){
			$this->evidence['native_connected_ns'] = hrtime(true);
		}
		$remaining = intdiv($started + 1_000_000 - hrtime(true), 1000);
		if($remaining > 0){ usleep($remaining); }
	}

	/** @param \Closure(): bool $condition */
	private function waitFor(\Closure $condition, bool $advanceTransport = true) : void{
		$deadline = hrtime(true) + 10_000_000_000;
		while(!$condition()){
			$this->tick($advanceTransport);
			if(hrtime(true) >= $deadline){
				$failure = $this->client->getFailureState();
				self::fail('TCP/native deadline; client=' . $this->client->getState()->name . '; failure=' . ($failure === null ? 'none' : $failure->name) . '; server=' . implode(',', array_map(static fn(ExtWebRtcPeer $peer) => $peer->getState() . '/' . ($peer->getFailureState() ?? 'none'), $this->peers)) . '; events=' . implode(',', $this->listener->events));
			}
		}
	}

	/** @return resource */
	private function socket(){
		$socket = stream_socket_client('tcp://' . $this->host->getAddress(), $code, $error, 1);
		self::assertNotFalse($socket);
		self::assertTrue(stream_set_blocking($socket, false));
		$this->sockets[] = $socket;
		return $socket;
	}

	/** @param resource $socket */
	private function write($socket, string $wire, bool $advanceTransport = true) : void{
		$offset = 0;
		$this->waitFor(function() use ($socket, $wire, &$offset) : bool{
			$written = fwrite($socket, substr($wire, $offset, 113));
			self::assertNotFalse($written);
			$offset += $written;
			return $offset === strlen($wire);
		}, $advanceTransport);
	}

	/** @param resource $socket */
	private function response($socket, bool $advanceTransport = true) : string{
		$wire = '';
		$this->waitFor(function() use ($socket, &$wire) : bool{
			$bytes = fread($socket, 65536);
			self::assertNotFalse($bytes);
			$wire .= $bytes;
			return feof($socket);
		}, $advanceTransport);
		fclose($socket);
		self::assertSame(1, substr_count($wire, 'HTTP/1.1 '));
		self::assertSame(0, $this->host->getConnectionCount());
		self::assertSame(0, $this->host->getBufferedBytes());
		self::assertSame(1, preg_match('/\r\nContent-Length: ([0-9]+)\r\n/', $wire, $match));
		[, $body] = explode("\r\n\r\n", $wire, 2);
		self::assertSame((int) $match[1], strlen($body));
		return $wire;
	}

	private function offer() : string{
		$this->channels[Channel::RELIABLE->name] = $this->client->createDataChannel('ReliableDataChannel');
		$this->channels[Channel::UNRELIABLE->name] = $this->client->createDataChannel('UnreliableDataChannel', DataChannelOptions::create()->setUnordered(true)->setMaxRetransmits(0));
		$this->waitFor(fn() => $this->client->getGatheringState() === GatheringState::COMPLETE);
		$sdp = $this->client->getLocalDescription();
		self::assertNotNull($sdp);
		self::assertMatchesRegularExpression('/a=candidate:[^\r\n]+ typ host/', $sdp);
		self::assertStringNotContainsString(' typ srflx', $sdp);
		self::assertStringNotContainsString(' typ relay', $sdp);
		return $this->signedOffer($sdp);
	}

	private function signedOffer(string $sdp, ?int $now = null, ?IdentityFixture $fixture = null) : string{
		$signed = ($fixture ?? $this->fixture)->offer($sdp, $now ?? time());
		self::assertSame(1, preg_match('/a=identity:[^\r\n]+/', $signed, $match));
		$offset = strpos($sdp, "\nm=");
		self::assertNotFalse($offset);
		return substr($sdp, 0, $offset + 1) . $match[0] . "\r\n" . substr($sdp, $offset + 1);
	}

	private static function post(string $offer, string $networkId = 'native%3Aopaque') : string{
		return "POST /v1/join/$networkId HTTP/1.1\r\nHost: test\r\nContent-Type: application/sdp\r\nContent-Length: " . strlen($offer) . "\r\n\r\n" . $offer;
	}

	private function answer(string $offer) : SdpIdentity{
		$socket = $this->socket();
		$local = stream_socket_get_name($socket, false);
		self::assertNotFalse($local);
		$this->evidence['signaling_peer_port'] = (int) substr($local, strrpos($local, ':') + 1);
		$started = hrtime(true);
		$this->write($socket, self::post($offer));
		$wire = $this->response($socket);
		$this->evidence['post_ms'] = (hrtime(true) - $started) / 1_000_000;
		$this->evidence['http_answer_ns'] = hrtime(true);
		self::assertStringStartsWith("HTTP/1.1 200 OK\r\n", $wire);
		self::assertStringContainsString("Content-Type: application/sdp\r\n", $wire);
		[, $body] = explode("\r\n\r\n", $wire, 2);
		self::assertCount(1, $this->peers);
		self::assertTrue($this->peers[0]->isGatheringComplete());
		self::assertMatchesRegularExpression('/a=candidate:[^\r\n]+ typ host/', $body);
		self::assertMatchesRegularExpression('/\r\na=fingerprint:[^\r\n]+\r\na=identity:[^\r\n]+\r\nm=application /', $body);
		$answer = SdpIdentity::fromSdp($body, $this->config);
		AnswerSignatures::verify($answer);
		self::assertSame('operator.test', $answer->providerDomain);
		self::assertNotNull($answer->token);
		$parts = explode('.', $answer->token);
		$claims = json_decode(base64_decode(strtr($parts[1], '-_', '+/'), true) ?: '', true, 16, JSON_THROW_ON_ERROR);
		self::assertIsArray($claims);
		self::assertSame('issuer', $claims['iss']);
		self::assertSame('game', $claims['aud']);
		self::assertSame('player', $claims['sub']);
		self::assertIsInt($claims['exp']);
		self::assertGreaterThan(time(), $claims['exp']);
		self::assertSame($this->peers[0]->getLocalDescription(), $answer->sdpWithoutIdentity);
		self::assertSame([], $this->listener->connections);
		self::assertSame(['answer'], $this->listener->events);
		return $answer;
	}

	private function connect(SdpIdentity $answer) : void{
		$started = hrtime(true);
		$this->client->setRemoteAnswer($answer->sdpWithoutIdentity);
		$this->waitFor(fn() => isset($this->listener->connections[1]) && $this->channels['RELIABLE']->isOpen() && $this->channels['UNRELIABLE']->isOpen());
		$this->evidence['channels_ms'] = (hrtime(true) - $started) / 1_000_000;
		$this->evidence['both_channels_ns'] = hrtime(true);
		self::assertSame('CONNECTED', $this->client->getState()->name);
		self::assertSame('CONNECTED', $this->peers[0]->getState());
		self::assertNull($this->client->getFailureState());
		self::assertNull($this->peers[0]->getFailureState());
		self::assertSame(ConnectionState::OPEN, $this->listener->connections[1]->getState());
		self::assertSame('native:opaque', $this->listener->connections[1]->getNetworkId());
		self::assertSame('player', $this->listener->connections[1]->getIdentity()->subject);
		self::assertSame('issuer', $this->listener->connections[1]->getIdentity()->claims['iss']);
		self::assertSame('game', $this->listener->connections[1]->getIdentity()->claims['aud']);
		self::assertSame($this->client->getLocalFingerprint(), $this->peers[0]->getRemoteFingerprint());
		self::assertStringContainsString($this->client->getRemoteFingerprint() ?? 'missing', $answer->canonicalFingerprints);
		foreach(Channel::cases() as $channel){
			$raw = $this->channels[$channel->name];
			$info = $this->peers[0]->getChannelInfo($channel);
			self::assertTrue($info['open']);
			self::assertFalse($info['closed']);
			self::assertSame($channel === Channel::RELIABLE ? 'ReliableDataChannel' : 'UnreliableDataChannel', $raw->getLabel());
			self::assertSame($raw->getLabel(), $info['label']);
			self::assertSame('', $info['protocol']);
			self::assertSame('', $raw->getProtocol());
			self::assertSame($channel === Channel::UNRELIABLE, $info['unordered']);
			self::assertSame($info['unordered'], $raw->isUnordered());
			self::assertSame($channel === Channel::UNRELIABLE ? 0 : null, $info['maxRetransmits']);
			self::assertSame($info['maxRetransmits'], $raw->getMaxRetransmits());
			self::assertNull($info['maxPacketLifeTime']);
			self::assertNull($raw->getMaxPacketLifeTime());
			self::assertSame(512, $raw->getMaxMessageSize());
		}
	}

	public function testRealTcpSignedNativeExchangeBidirectionalPayloadAndCleanup() : void{
		$socket = $this->socket();
		$started = hrtime(true);
		$this->write($socket, "GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
		$wire = $this->response($socket);
		$this->evidence['get_ms'] = (hrtime(true) - $started) / 1_000_000;
		self::assertStringStartsWith("HTTP/1.1 200 OK\r\n", $wire);
		self::assertStringContainsString("Content-Type: application/json\r\n", $wire);
		[, $json] = explode("\r\n\r\n", $wire, 2);
		self::assertSame(['name' => 'Native TCP', 'protocol' => 1, 'version' => 'fixture', 'level' => 'World', 'players' => 0, 'maxPlayers' => 2, 'gameType' => 0], json_decode($json, true, 16, JSON_THROW_ON_ERROR));
		$offer = $this->offer();
		$verified = $this->fixture->verifier()->verify(SdpIdentity::fromSdp($offer, $this->config), time());
		self::assertSame('player', $verified->subject);
		$answer = $this->answer($offer);
		$this->connect($answer);
		$this->host->stop();
		self::assertSame(ConnectionState::OPEN, $this->listener->connections[1]->getState());
		$connection = $this->listener->connections[1];
		self::assertInstanceOf(SignalingPeerConnection::class, $connection);
		$address = $connection->getSignalingPeerAddress();
		self::assertNotNull($address);
		self::assertSame('127.0.0.1', $address->ip);
		self::assertSame($this->evidence['signaling_peer_port'], $address->port);
		$codec = new FrameCodec($this->config);
		$bytes = 0;
		foreach(Channel::cases() as $channel){
			$payloads = ['', "\0\x01\xfe\xffnether\0", str_repeat("\0\xff", 255) . 'x'];
			if($channel === Channel::RELIABLE){ $payloads[] = str_repeat("\0\xff", 2048); }
			foreach($payloads as $payload){
				$raw = $this->channels[$channel->name];
				$before = count($this->listener->payloads);
				foreach($codec->encode($payload, 512) as $frame){ $raw->send($frame); }
				$this->waitFor(fn() => count($this->listener->payloads) > $before);
				self::assertSame([1, $payload, $channel], $this->listener->payloads[$before]);
				$accepted = [];
				self::assertSame(SendResult::ACCEPTED, $this->listener->connections[1]->send($payload, $channel, accepted: static function(bool $ok) use (&$accepted) : void{ $accepted[] = $ok; }));
				$received = '';
				$remaining = max(0, (int) ceil(strlen($payload) / 511) - 1);
				$this->waitFor(function() use ($raw, &$received, &$remaining) : bool{
					$frame = $raw->receive();
					if($frame === null){ return false; }
					self::assertNotSame('', $frame);
					self::assertLessThanOrEqual(512, strlen($frame));
					self::assertSame($remaining, ord($frame[0]));
					$received .= substr($frame, 1);
					return $remaining-- === 0;
				});
				self::assertSame($payload, $received);
				self::assertSame([true], $accepted);
				self::assertNull($raw->receive());
				$bytes += strlen($payload);
			}
		}
		$this->evidence['payload_bytes_each_direction'] = $bytes;
		self::assertCount(7, $this->listener->payloads);
		$this->transport->stop();
		$this->transport->stop();
		self::assertSame(['answer', 'open', 'close'], $this->listener->events);
		self::assertCount(1, $this->listener->closed);
		self::assertSame(ConnectionState::CLOSED, $this->listener->connections[1]->getState());
		$this->waitFor(fn() => $this->channels['RELIABLE']->isClosed() && $this->channels['UNRELIABLE']->isClosed());
	}

	/** @return iterable<string, array{string, int}> */
	public static function rejectedOffers() : iterable{
		yield 'missing identity' => ['missing', 403];
		yield 'invalid envelope' => ['envelope', 403];
		yield 'invalid JWT signature' => ['token', 403];
		yield 'invalid fingerprint JWS' => ['jws', 403];
		yield 'modified fingerprint' => ['fingerprint', 403];
		yield 'expired token' => ['expired', 403];
		yield 'untrusted issuer key' => ['untrusted', 403];
		yield 'wrong audience with valid signature' => ['audience', 403];
		yield 'malformed SDP' => ['sdp', 400];
	}

	private static function corruptSignature(string $compact) : string{
		$parts = explode('.', $compact);
		$parts[2] = ($parts[2][0] === 'A' ? 'B' : 'A') . substr($parts[2], 1);
		return implode('.', $parts);
	}

	#[DataProvider('rejectedOffers')]
	public function testRejectedTcpOffersNeverCreateNativePeer(string $kind, int $status) : void{
		$offer = $this->offer();
		$base = $this->client->getLocalDescription();
		self::assertNotNull($base);
		if($kind === 'missing'){ $offer = $base; }
		elseif($kind === 'expired'){ $offer = $this->signedOffer($base, time() - 120); }
		elseif($kind === 'untrusted'){ $offer = $this->signedOffer($base, fixture: new IdentityFixture()); }
		elseif($kind === 'sdp'){ $offer .= "\0"; }
		elseif($kind === 'fingerprint'){
			$offer = preg_replace_callback('/(a=fingerprint:sha-256 )([0-9A-F])/', static fn(array $match) => $match[1] . ($match[2] === 'A' ? 'B' : 'A'), $offer) ?? throw new \RuntimeException('Fingerprint mutation failed');
		}else{
			self::assertSame(1, preg_match('/a=identity:([^\r\n]+)/', $offer, $match));
			$decoded = base64_decode($match[1], true);
			self::assertNotFalse($decoded);
			$envelope = json_decode($decoded, true, 16, JSON_THROW_ON_ERROR);
			self::assertIsArray($envelope);
			self::assertIsString($envelope['assertion']);
			$assertion = json_decode($envelope['assertion'], true, 16, JSON_THROW_ON_ERROR);
			self::assertIsArray($assertion);
			if($kind === 'envelope'){ $replacement = '!!!'; }
			else{
				if($kind === 'audience'){
					self::assertIsString($assertion['token']);
					$parts = explode('.', $assertion['token']);
					$claims = json_decode(base64_decode(strtr($parts[1], '-_', '+/'), true) ?: '', true, 16, JSON_THROW_ON_ERROR);
					self::assertIsArray($claims);
					$claims['aud'] = 'different-game';
					$input = $parts[0] . '.' . rtrim(strtr(base64_encode(json_encode($claims, JSON_THROW_ON_ERROR)), '+/', '-_'), '=');
					self::assertTrue(openssl_sign($input, $signature, $this->fixture->issuer, OPENSSL_ALGO_SHA256));
					$assertion['token'] = $input . '.' . rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');
				}else{
					$field = $kind === 'token' ? 'token' : 'fingerprints';
					self::assertIsString($assertion[$field]);
					$assertion[$field] = self::corruptSignature($assertion[$field]);
				}
				$envelope['assertion'] = json_encode($assertion, JSON_THROW_ON_ERROR);
				$replacement = base64_encode(json_encode($envelope, JSON_THROW_ON_ERROR));
			}
			$offer = str_replace($match[0], 'a=identity:' . $replacement, $offer);
		}
		$socket = $this->socket();
		$this->write($socket, self::post($offer));
		$wire = $this->response($socket);
		self::assertStringStartsWith("HTTP/1.1 $status ", $wire);
		self::assertStringContainsString("Content-Type: text/plain; charset=utf-8\r\n", $wire);
		self::assertStringNotContainsString('a=identity:', $wire);
		self::assertSame([], $this->peers);
		self::assertSame([], $this->listener->connections);
		self::assertSame([], $this->listener->answers);
		self::assertLessThanOrEqual(1, count($this->listener->closed));
		$this->tick();
		self::assertSame([], $this->peers);
	}

	/** @return resource */
	private function pendingOffer(){
		$offer = $this->offer();
		$socket = $this->socket();
		$this->write($socket, self::post($offer), false);
		$this->waitFor(fn() => $this->http->getState(1) === HttpState::PENDING, false);
		self::assertSame(1, $this->http->getTransportId(1));
		self::assertSame([], $this->peers);
		return $socket;
	}

	public function testTcpEofBeforeCompleteBodyDoesNotAdmitPeer() : void{
		$offer = $this->offer();
		$socket = $this->socket();
		$this->write($socket, substr(self::post($offer), 0, -1));
		self::assertTrue(stream_socket_shutdown($socket, STREAM_SHUT_WR));
		self::assertStringStartsWith('HTTP/1.1 400 ', $this->response($socket));
		self::assertSame([], $this->peers);
		self::assertSame([], $this->listener->events);
	}

	/** @return iterable<string, array{bool}> */
	public static function cancelModes() : iterable{
		yield 'cancel gathering' => [false];
		yield 'shutdown gathering' => [true];
	}

	#[DataProvider('cancelModes')]
	public function testCancelAndShutdownDuringNativeGathering(bool $shutdown) : void{
		$socket = $this->pendingOffer();
		$this->transport->poll();
		self::assertCount(1, $this->peers);
		self::assertSame([], $this->listener->answers);
		if($shutdown){ $this->host->stop(); }
		else{ $this->http->cancel(1); $this->host->poll(1000); }
		self::assertSame('CLOSED', $this->peers[0]->getState());
		self::assertSame(HttpState::CLOSED, $this->http->getState(1));
		self::assertSame(0, $this->host->getConnectionCount());
		$this->tick();
		$this->transport->stop();
		self::assertSame(['close'], $this->listener->events);
		self::assertCount(1, $this->listener->closed);
		fclose($socket);
	}

	public function testDisconnectedTcpPendingAnswerExpiresAndReleasesNativePeer() : void{
		$socket = $this->pendingOffer();
		$this->transport->poll();
		fclose($socket);
		$this->clockOffset += $this->config->signalingTimeoutSeconds + 1;
		$this->host->poll(1000);
		self::assertSame('CLOSED', $this->peers[0]->getState());
		$this->waitFor(fn() => $this->host->getConnectionCount() === 0);
		self::assertSame([], $this->listener->answers);
		self::assertSame(['close'], $this->listener->events);
	}

	public function testWebRtcTimeoutAfterDeliveredHttp200HasOneClose() : void{
		$this->answer($this->offer());
		$this->clockOffset += $this->config->connectTimeoutSeconds + 1;
		$this->tick();
		self::assertSame(['answer', 'close'], $this->listener->events);
		self::assertSame('connect_timeout', $this->listener->closed[0][1]);
		self::assertSame('CLOSED', $this->peers[0]->getState());
		$this->tick();
		$this->transport->stop();
		self::assertCount(1, $this->listener->closed);
	}

	public function testRemoteChannelCloseClosesServerExactlyOnce() : void{
		$this->connect($this->answer($this->offer()));
		$this->channels['RELIABLE']->close();
		$this->waitFor(fn() => $this->listener->closed !== []);
		self::assertSame(['answer', 'open', 'close'], $this->listener->events);
		self::assertSame('CLOSED', $this->peers[0]->getState());
		$this->transport->stop();
		self::assertCount(1, $this->listener->closed);
	}

	public function testListenerExceptionPropagatesAndExplicitShutdownReleasesPeer() : void{
		$this->listener->opened = static function() : void{ throw new \RuntimeException('listener failure'); };
		$answer = $this->answer($this->offer());
		$this->client->setRemoteAnswer($answer->sdpWithoutIdentity);
		try{
			$this->waitFor(fn() => false);
			self::fail('Listener exception swallowed');
		}catch(\RuntimeException $e){
			self::assertSame('listener failure', $e->getMessage());
		}
		$this->transport->stop();
		self::assertSame(['answer', 'open', 'close'], $this->listener->events);
		self::assertSame('CLOSED', $this->peers[0]->getState());
	}

	public function testAuthenticatedMalformedNativeOfferReturns500AndClosesBackend() : void{
		$offer = $this->offer();
		$offer = str_replace('m=application', 'm=invalid', $offer);
		$socket = $this->socket();
		$this->write($socket, self::post($offer));
		self::assertStringStartsWith('HTTP/1.1 500 ', $this->response($socket));
		self::assertCount(1, $this->peers);
		self::assertSame('CLOSED', $this->peers[0]->getState());
		self::assertSame(['close'], $this->listener->events);
		self::assertSame([], $this->listener->connections);
	}

	public function testSignedFingerprintForDifferentCertificateCannotOpenConnection() : void{
		$this->offer();
		$base = $this->client->getLocalDescription();
		self::assertNotNull($base);
		$base = preg_replace('/a=fingerprint:sha-256 [0-9A-F:]+/', 'a=fingerprint:sha-256 ' . str_repeat('AA:', 31) . 'AA', $base) ?? throw new \RuntimeException('Fingerprint replacement failed');
		$answer = $this->answer($this->signedOffer($base));
		$this->client->setRemoteAnswer($answer->sdpWithoutIdentity);
		$this->waitFor(fn() => $this->listener->closed !== []);
		self::assertSame(['answer', 'close'], $this->listener->events);
		self::assertSame([], $this->listener->connections);
		self::assertSame('backend_failed', $this->listener->closed[0][1]);
		self::assertSame('CLOSED', $this->peers[0]->getState());
	}

	public function testReentrantHostShutdownAtAnswerDiscardsStale200() : void{
		$this->listener->answered = function() : void{ $this->host->stop(); };
		$socket = $this->socket();
		$this->write($socket, self::post($this->offer()));
		$wire = '';
		$this->waitFor(function() use ($socket, &$wire) : bool{
			$bytes = fread($socket, 65536);
			self::assertNotFalse($bytes);
			$wire .= $bytes;
			return feof($socket);
		});
		self::assertSame('', $wire);
		self::assertSame(['answer', 'close'], $this->listener->events);
		self::assertSame('CLOSED', $this->peers[0]->getState());
		self::assertSame(0, $this->host->getConnectionCount());
	}

	public function testMultiplePendingNativePeersShutdownWithoutOrphans() : void{
		$offer = $this->offer();
		for($id = 1; $id <= 3; ++$id){
			$socket = $this->socket();
			$this->write($socket, self::post($offer, 'peer-' . $id), false);
			$this->waitFor(fn() => $this->http->getState($id) === HttpState::PENDING, false);
		}
		$this->transport->poll();
		self::assertCount(3, $this->peers);
		self::assertSame(3, $this->host->getConnectionCount());
		$this->host->stop();
		$this->transport->stop();
		$this->host->stop();
		foreach($this->peers as $peer){ self::assertSame('CLOSED', $peer->getState()); }
		self::assertSame(['close', 'close', 'close'], $this->listener->events);
		self::assertSame([1, 2, 3], array_column($this->listener->closed, 0));
		self::assertSame(0, $this->host->getConnectionCount());
		self::assertSame(0, $this->host->getBufferedBytes());
	}

	public function testTwoTcpNativeConnectionsOpenAndRoutePayloadsIndependently() : void{
		$second = new PeerConnection(PeerConnectionOptions::create()->setMaxMessageSize(512)->setIceTcpEnabled(false));
		$channels = [];
		try{
			$firstOffer = $this->offer();
			$channels[] = $second->createDataChannel('ReliableDataChannel');
			$channels[] = $second->createDataChannel('UnreliableDataChannel', DataChannelOptions::create()->setUnordered(true)->setMaxRetransmits(0));
			$this->waitFor(fn() => $second->getGatheringState() === GatheringState::COMPLETE);
			$base = $second->getLocalDescription();
			self::assertNotNull($base);
			$sockets = [$this->socket(), $this->socket()];
			$this->write($sockets[0], self::post($firstOffer, 'first'), false);
			$this->write($sockets[1], self::post($this->signedOffer($base), 'second'), false);
			$wires = ['', ''];
			$this->waitFor(function() use ($sockets, &$wires) : bool{
				foreach($sockets as $index => $socket){
					$bytes = fread($socket, 65536);
					self::assertNotFalse($bytes);
					$wires[$index] .= $bytes;
				}
				return feof($sockets[0]) && feof($sockets[1]);
			});
			foreach($wires as $index => $wire){
				self::assertStringStartsWith("HTTP/1.1 200 OK\r\n", $wire);
				[, $body] = explode("\r\n\r\n", $wire, 2);
				$answer = SdpIdentity::fromSdp($body, $this->config);
				AnswerSignatures::verify($answer);
				($index === 0 ? $this->client : $second)->setRemoteAnswer($answer->sdpWithoutIdentity);
				fclose($sockets[$index]);
			}
			$this->waitFor(fn() => count($this->listener->connections) === 2 && $channels[0]->isOpen() && $channels[1]->isOpen());
			self::assertSame('first', $this->listener->connections[1]->getNetworkId());
			self::assertSame('second', $this->listener->connections[2]->getNetworkId());
			self::assertSame($this->client->getLocalFingerprint(), $this->peers[0]->getRemoteFingerprint());
			self::assertSame($second->getLocalFingerprint(), $this->peers[1]->getRemoteFingerprint());
			$this->channels['RELIABLE']->send("\0first\xff");
			$channels[0]->send("\0second\x00");
			$this->waitFor(fn() => count($this->listener->payloads) === 2);
			self::assertContains([1, "first\xff", Channel::RELIABLE], $this->listener->payloads);
			self::assertContains([2, "second\x00", Channel::RELIABLE], $this->listener->payloads);
			$this->transport->close(1);
			self::assertSame(ConnectionState::OPEN, $this->listener->connections[2]->getState());
			$channels[1]->send("\0still alive");
			$this->waitFor(fn() => count($this->listener->payloads) === 3);
			self::assertSame([2, 'still alive', Channel::UNRELIABLE], $this->listener->payloads[2]);
			$this->transport->stop();
			self::assertSame([1, 2], array_column($this->listener->closed, 0));
			self::assertSame(0, $this->host->getConnectionCount());
		}finally{
			foreach($channels as $channel){ $channel->close(); }
			$second->close();
		}
	}
}
