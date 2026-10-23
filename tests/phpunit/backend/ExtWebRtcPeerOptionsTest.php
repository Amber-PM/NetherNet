<?php

declare(strict_types=1);

namespace amber\nethernet\tests\backend;

use amber\nethernet\backend\ExtWebRtcPeer;
use amber\nethernet\TransportConfig;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ExtWebRtcPeerOptionsTest extends TestCase{
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
		new ExtWebRtcPeer(new TransportConfig(), $begin, $end, $bind);
	}
}
