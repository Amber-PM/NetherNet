<?php

declare(strict_types=1);

namespace amber\nethernet\tests\backend;

use amber\nethernet\backend\ExtRtcPeer;
use amber\nethernet\TransportConfig;
use amber\nethernet\TransportException;
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

	public function testUdpMuxIsRejectedInsteadOfIgnored() : void{
		try{
			new ExtRtcPeer(new TransportConfig(), 19133, 19133, '127.0.0.1', true);
			self::fail('UDP mux request was accepted');
		}catch(TransportException $e){
			self::assertSame('backend_unsupported', $e->errorCode);
		}
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
}
