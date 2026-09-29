<?php

/*
 * SPDX-License-Identifier: LGPL-3.0-only
 */

declare(strict_types=1);

use Composer\Autoload\ClassLoader;

$autoloadPath = __DIR__ . '/../vendor/autoload.php';
if(!file_exists($autoloadPath)){
	fwrite(STDERR, "Composer autoloader not found at " . $autoloadPath . "\n");
	exit(1);
}

$loader = require $autoloadPath;
if(!$loader instanceof ClassLoader){
	fwrite(STDERR, "Composer autoloader did not return a ClassLoader instance\n");
	exit(1);
}

if(!function_exists('hrtime')){
	fwrite(STDERR, "hrtime() is not available in the current PHP environment\n");
	exit(1);
}

$start = hrtime(true);
$end = hrtime(true);
if($end < $start){
	fwrite(STDERR, "hrtime() is not monotonic or usable\n");
	exit(1);
}

$scriptFilename = $_SERVER['SCRIPT_FILENAME'] ?? '';
$currentScript = is_string($scriptFilename) ? realpath($scriptFilename) : false;
$thisScript = realpath(__FILE__);

if($currentScript !== false && $thisScript !== false && $currentScript === $thisScript){
	echo "Benchmark bootstrap OK\n";
	exit(0);
}

return $loader;
