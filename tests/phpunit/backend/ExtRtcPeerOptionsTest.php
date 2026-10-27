<?php

declare(strict_types=1);

namespace amber\nethernet\tests\backend;

use amber\nethernet\backend\ExtRtcPeer;
use amber\nethernet\TransportConfig;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ExtRtcPeerOptionsTest extends TestCase{
	/** @return iterable<string, array{int, int, ?string}> */
	public static function invalidOptions() : iterable{
		yield 'missing end' => [19133, 0, null];
		yield 'missing begin' => [0, 19233, null];
		yield 'negative begin' => [-1, 19233, null];
		yield 'above maximum' => [19133, 65536, null];
		yield 'reversed' => [19233, 19133, null];
		yield 'hostname' => [0, 0, 'localhost'];
		yield 'empty bind' => [0, 0, ''];
		yield 'bind with port' => [0, 0, '127.0.0.1:19133'];
		yield 'malformed IPv6' => [0, 0, ':::'];
	}

	#[DataProvider('invalidOptions')]
	public function testRejectsInvalidOptionsBeforeNativeConstruction(int $begin, int $end, ?string $bind) : void{
		$this->expectException(\InvalidArgumentException::class);
		new ExtRtcPeer(new TransportConfig(), $begin, $end, $bind);
	}

	/** @return iterable<string, array{int, int, ?string, bool}> */
	public static function invalidMuxOptions() : iterable{
		yield 'ephemeral port' => [0, 0, '127.0.0.1', false];
		yield 'port range' => [19133, 19134, '127.0.0.1', false];
		yield 'windows default bind' => [19133, 19133, null, true];
		yield 'windows IPv4 wildcard' => [19133, 19133, '0.0.0.0', true];
		yield 'windows IPv6 wildcard' => [19133, 19133, '::', true];
		yield 'windows expanded IPv6 wildcard' => [19133, 19133, '0:0:0:0:0:0:0:0', true];
	}

	#[DataProvider('invalidMuxOptions')]
	public function testUnsafeMuxOptionsAreRejected(int $begin, int $end, ?string $bind, bool $windows) : void{
		$this->expectException(\InvalidArgumentException::class);
		ExtRtcPeer::assertMuxOptions($begin, $end, $bind, $windows);
	}

	/** @return iterable<string, array{?string, bool}> */
	public static function validMuxOptions() : iterable{
		yield 'linux default bind' => [null, false];
		yield 'linux wildcard' => ['0.0.0.0', false];
		yield 'windows IPv4' => ['127.0.0.1', true];
		yield 'windows IPv6' => ['::1', true];
	}

	#[DataProvider('validMuxOptions')]
	public function testFixedPortMuxOptionsAreAccepted(?string $bind, bool $windows) : void{
		ExtRtcPeer::assertMuxOptions(19133, 19133, $bind, $windows);
		$this->addToAssertionCount(1);
	}

	public function testMuxRangeIsRejectedBeforeNativeConstruction() : void{
		$this->expectException(\InvalidArgumentException::class);
		new ExtRtcPeer(new TransportConfig(), 19133, 19134, '127.0.0.1', true);
	}

	public function testMissingExtensionIsReportedWithoutAutoloadingNativeClasses() : void{
		$autoload = dirname(__DIR__, 3) . '/vendor/autoload.php';
		$code = 'require ' . var_export($autoload, true) . ';' .
			'spl_autoload_register(static function(string $c) : void{ if(str_starts_with($c, "amber\\\\rtc\\\\")){ echo "autoload:", $c, "\n"; } });' .
			'try{ \amber\nethernet\backend\ExtRtcPeer::assertAvailable(); echo "available\n"; }' .
			'catch(\amber\nethernet\TransportException $e){ echo $e->errorCode, "\n"; }';
		// windows escapeshellarg replaces double quotes, so skip the shell
		$process = proc_open([PHP_BINARY, '-n', '-r', $code], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		self::assertIsResource($process);
		$output = stream_get_contents($pipes[1]);
		$errors = stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		self::assertSame(0, proc_close($process), $output . $errors);
		self::assertSame('', $errors);
		self::assertSame("backend_unavailable\n", $output);
	}

	/** @return iterable<string, array{string}> */
	public static function invalidAdvertisedAddresses() : iterable{
		yield 'hostname' => ['example.com'];
		yield 'empty' => [''];
		yield 'with port' => ['203.0.113.7:19133'];
		yield 'IPv4 wildcard' => ['0.0.0.0'];
		yield 'IPv6 wildcard' => ['::'];
	}

	#[DataProvider('invalidAdvertisedAddresses')]
	public function testInvalidAdvertisedAddressIsRejectedBeforeNativeConstruction(string $address) : void{
		$this->expectException(\InvalidArgumentException::class);
		new ExtRtcPeer(new TransportConfig(), 19133, 19133, null, false, $address);
	}

	public function testAdvertisedAddressFollowsEachHostCandidate() : void{
		$sdp = "v=0\r\na=candidate:1 1 UDP 2122317823 172.18.0.5 19133 typ host\r\na=candidate:2 1 UDP 2122317567 10.0.0.9 19134 typ host generation 0\r\na=end-of-candidates\r\n";
		self::assertSame(
			"v=0\r\na=candidate:1 1 UDP 2122317823 172.18.0.5 19133 typ host\r\na=candidate:1a 1 UDP 2122317822 203.0.113.7 19133 typ host\r\n" .
			"a=candidate:2 1 UDP 2122317567 10.0.0.9 19134 typ host generation 0\r\na=candidate:2a 1 UDP 2122317566 203.0.113.7 19134 typ host generation 0\r\na=end-of-candidates\r\n",
			ExtRtcPeer::withAdvertisedCandidates($sdp, '203.0.113.7')
		);
	}

	public function testAdvertisedAddressIsAddedOncePerPortAndFamily() : void{
		$sdp = "a=candidate:1 1 UDP 100 172.18.0.5 19133 typ host\na=candidate:2 1 UDP 99 192.168.1.4 19133 typ host\na=candidate:3 1 UDP 98 fd00::5 19133 typ host\na=candidate:4 1 UDP 97 172.18.0.5 19135 typ srflx raddr 0.0.0.0 rport 0\na=candidate:5 2 UDP 96 172.18.0.5 19136 typ host";
		self::assertSame(
			"a=candidate:1 1 UDP 100 172.18.0.5 19133 typ host\na=candidate:1a 1 UDP 99 203.0.113.7 19133 typ host\na=candidate:2 1 UDP 99 192.168.1.4 19133 typ host\na=candidate:3 1 UDP 98 fd00::5 19133 typ host\na=candidate:4 1 UDP 97 172.18.0.5 19135 typ srflx raddr 0.0.0.0 rport 0\na=candidate:5 2 UDP 96 172.18.0.5 19136 typ host",
			ExtRtcPeer::withAdvertisedCandidates($sdp, '203.0.113.7')
		);
		self::assertSame(
			"a=candidate:3 1 UDP 98 fd00::5 19133 typ host\r\na=candidate:3a 1 UDP 97 2001:db8::7 19133 typ host",
			ExtRtcPeer::withAdvertisedCandidates("a=candidate:3 1 UDP 98 fd00::5 19133 typ host", '2001:db8::7')
		);
	}

	public function testAlreadyAdvertisedAddressIsNotDuplicated() : void{
		$sdp = "a=candidate:1 1 UDP 100 203.0.113.7 19133 typ host\r\na=candidate:2 1 UDP 99 172.18.0.5 19133 typ host\r\n";
		self::assertSame($sdp, ExtRtcPeer::withAdvertisedCandidates($sdp, '203.0.113.7'));
	}
}
