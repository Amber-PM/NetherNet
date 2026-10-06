<?php

declare(strict_types=1);

namespace amber\nethernet\tests\backend;

use PHPUnit\Framework\TestCase;

final class BackendAvailabilityTest extends TestCase{
	public function testMissingExtensionHasExplicitErrorWithoutInstantiatingNativeTypes() : void{
		$root = dirname(__DIR__, 3);
		$script = 'require ' . var_export($root . '/vendor/autoload.php', true) . ';' .
			'try{ \amber\nethernet\backend\ExtWebRtcPeer::assertAvailable(); exit(1); }' .
			'catch(\amber\nethernet\TransportException $e){ echo $e->errorCode; }';
		$output = [];
		$code = 0;
		exec(escapeshellarg(PHP_BINARY) . ' -n -r ' . escapeshellarg($script), $output, $code);
		self::assertSame(0, $code);
		self::assertSame(['backend_unavailable'], $output);
	}
}
