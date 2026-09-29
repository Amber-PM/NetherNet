<?php

/*
 * SPDX-License-Identifier: LGPL-3.0-only
 */

declare(strict_types=1);

namespace amber\nethernet\tests;

use Composer\Autoload\ClassLoader;
use PHPUnit\Framework\TestCase;
use function array_map;
use function dirname;
use function realpath;

final class BootstrapTest extends TestCase{

	public function testComposerAutoloadConfiguration() : void{
		$projectRoot = dirname(__DIR__, 2);
		$loader = require $projectRoot . '/vendor/autoload.php';

		self::assertInstanceOf(ClassLoader::class, $loader);

		$prefixes = $loader->getPrefixesPsr4();

		$expectedSrc = realpath($projectRoot . '/src');
		self::assertNotFalse($expectedSrc);
		self::assertArrayHasKey('amber\\nethernet\\', $prefixes);
		$srcPaths = array_map(static fn(string $path) : string|false => realpath($path), $prefixes['amber\\nethernet\\']);
		self::assertContains($expectedSrc, $srcPaths);

		$expectedTests = realpath($projectRoot . '/tests/phpunit');
		self::assertNotFalse($expectedTests);
		self::assertArrayHasKey('amber\\nethernet\\tests\\', $prefixes);
		$testPaths = array_map(static fn(string $path) : string|false => realpath($path), $prefixes['amber\\nethernet\\tests\\']);
		self::assertContains($expectedTests, $testPaths);

		$canonicalCurrentFile = realpath(__FILE__);
		self::assertNotFalse($canonicalCurrentFile);

		$foundFile = $loader->findFile(self::class);
		self::assertIsString($foundFile);

		$canonicalFoundFile = realpath($foundFile);
		self::assertNotFalse($canonicalFoundFile);
		self::assertSame($canonicalCurrentFile, $canonicalFoundFile);
	}
}
