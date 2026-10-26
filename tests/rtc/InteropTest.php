<?php

declare(strict_types=1);

namespace amber\nethernet\tests\rtc;

use amber\nethernet\backend\ExtRtcPeer;
use amber\nethernet\backend\WebRtcPeer;
use amber\nethernet\Channel;
use amber\nethernet\ConnectionState;
use amber\nethernet\identity\ClientServerIdentityHandler;
use amber\nethernet\identity\SdpIdentity;
use amber\nethernet\SendResult;
use amber\nethernet\tests\identity\IdentityFixture;
use amber\nethernet\tests\transport\RecordingListener;
use amber\nethernet\Transport;
use amber\nethernet\TransportConfig;
use amber\rtc\RtcRuntime;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

#[Group('interop')]
final class InteropTest extends TestCase{
	/** @var resource|null */
	private $process = null;
	/** @var array<int, resource> */
	private array $pipes = [];
	private string $buffer = '';

	protected function tearDown() : void{
		foreach($this->pipes as $pipe){ fclose($pipe); }
		$this->pipes = [];
		if($this->process !== null){
			proc_terminate($this->process, 9);
			proc_close($this->process);
			$this->process = null;
		}
	}

	/**
	 * @param non-empty-string $prefix
	 * @param \Closure(): void $poll
	 */
	private function read(string $prefix, \Closure $poll) : string{
		$deadline = hrtime(true) + 15_000_000_000;
		while(($end = strpos($this->buffer, "\n")) === false){
			if(hrtime(true) >= $deadline){ self::fail('ext-webrtc client timed out waiting for ' . $prefix . '; stderr: ' . stream_get_contents($this->pipes[2])); }
			$this->buffer .= (string) fread($this->pipes[1], 65536);
			$poll();
			usleep(1000);
		}
		$line = substr($this->buffer, 0, $end);
		$this->buffer = substr($this->buffer, $end + 1);
		self::assertStringStartsWith($prefix, $line, 'Client reported: ' . $line);
		return substr($line, strlen($prefix));
	}

	private function write(string $line) : void{
		fwrite($this->pipes[0], $line . "\n");
		fflush($this->pipes[0]);
	}

	/** @return list<string> */
	private static function clientCommand() : array{
		// any executable speaking the support/webrtc-client.php line protocol, e.g. a pion client
		$client = getenv('NETHERNET_INTEROP_CLIENT');
		if(is_string($client) && $client !== ''){
			self::assertFileExists($client);
			return [$client];
		}
		$module = getenv('NETHERNET_WEBRTC_MODULE');
		self::assertIsString($module, 'NETHERNET_WEBRTC_MODULE must name the ext-webrtc module, or NETHERNET_INTEROP_CLIENT an interop client');
		self::assertFileExists($module);
		return [PHP_BINARY, '-n', '-d', 'extension=' . $module, __DIR__ . '/support/webrtc-client.php'];
	}

	/** @return iterable<string, array{bool}> */
	public static function muxModes() : iterable{
		yield 'own socket' => [false];
		yield 'udp mux' => [true];
	}

	#[DataProvider('muxModes')]
	public function testExtRtcServerInteroperatesWithIndependentClientInSeparateProcess(bool $mux) : void{
		$process = proc_open(self::clientCommand(), [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes);
		self::assertIsResource($process);
		$this->process = $process;
		$this->pipes = $pipes;
		stream_set_blocking($pipes[1], false);
		stream_set_blocking($pipes[2], false);

		$fixture = new IdentityFixture();
		$config = new TransportConfig(maxMessageBytes: 512);
		$port = ExtRtcPeerTest::freeUdpPort();
		$listener = new RecordingListener();
		$transport = new Transport($config, new ClientServerIdentityHandler($fixture->verifier(), $fixture->server), $listener, $mux
			? static fn() : WebRtcPeer => new ExtRtcPeer($config, $port, $port, '127.0.0.1', true)
			: static fn() : WebRtcPeer => new ExtRtcPeer($config));
		$poll = static function() use ($transport) : void{ $transport->poll(); };
		try{
			$offer = hex2bin($this->read('OFFER ', $poll));
			self::assertIsString($offer);
			$id = $transport->accept('interop', $fixture->offer($offer, time()));
			$listener->answered = function(int $answerId) use ($listener, $config) : void{
				$answer = SdpIdentity::fromSdp($listener->answers[$answerId], $config);
				self::assertNotNull($answer->token);
				$this->write('ANSWER ' . bin2hex($answer->sdpWithoutIdentity));
			};
			$fingerprint = $this->read('OPEN ', $poll);
			self::assertMatchesRegularExpression('/^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/', $fingerprint);
			ExtRtcPeerTest::waitFor(function() use ($transport, $listener, $id) : bool{ $transport->poll(); self::assertSame([], $listener->closed); return isset($listener->connections[$id]); });
			$connection = $listener->connections[$id];
			self::assertSame('player', $connection->getIdentity()->subject);

			$payload = str_repeat("\x00\xffinterop", 250);
			$this->write('SEND ' . bin2hex($payload));
			$this->read('SENT', $poll);
			ExtRtcPeerTest::waitFor(function() use ($transport, $listener) : bool{ $transport->poll(); self::assertSame([], $listener->closed); return count($listener->payloads) === 2; });
			self::assertContains([$id, $payload, Channel::RELIABLE], $listener->payloads);
			self::assertContains([$id, substr($payload, 0, 64), Channel::UNRELIABLE], $listener->payloads);

			$accepted = [];
			self::assertSame(SendResult::ACCEPTED, $connection->send($payload, accepted: function(bool $ok) use (&$accepted) : void{ $accepted[] = $ok; }));
			self::assertSame(SendResult::ACCEPTED, $connection->send('lossy', Channel::UNRELIABLE));
			[$reliable, $unreliable] = explode(' ', $this->read('RECEIVED ', $poll));
			self::assertSame($payload, hex2bin($reliable));
			self::assertSame("\0lossy", hex2bin($unreliable));
			self::assertSame([true], $accepted);

			$this->write('CLOSE');
			$this->read('CLOSED', $poll);
			ExtRtcPeerTest::waitFor(function() use ($transport, $listener) : bool{ $transport->poll(); return $listener->closed !== []; });
			self::assertSame(ConnectionState::CLOSED, $connection->getState());
			self::assertSame(0, RtcRuntime::getStats()['activePeers']);
		}finally{
			$transport->stop();
		}
	}
}
