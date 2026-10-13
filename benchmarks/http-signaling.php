<?php

declare(strict_types=1);

use amber\nethernet\signaling\HttpParseState;
use amber\nethernet\signaling\HttpRequestParser;
use amber\nethernet\TransportConfig;

require __DIR__ . '/bootstrap.php';

$iterations = filter_var($argv[1] ?? '1000', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 1000000]]);
if($iterations === false){
	fwrite(STDERR, "Usage: php benchmarks/http-signaling.php [1..1000000]\n");
	exit(1);
}
$config = new TransportConfig();
$get = "GET /v1/join HTTP/1.1\r\nHost: example.test\r\n\r\n";
$offer = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";
$body = $offer . str_repeat('a', 4096 - strlen($offer));
$largeBody = $offer . str_repeat('a', $config->maxSdpBytes - strlen($offer));
$post = static fn(string $sdp) => "POST /v1/join/opaque-id HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/sdp\r\nContent-Length: " . strlen($sdp) . "\r\n\r\n" . $sdp;
$cases = [
	'get' => [$get, strlen($get), true],
	'post_4k' => [$post($body), strlen($post($body)), true],
	'post_4k_fragmented' => [$post($body), 37, true],
	'post_64k' => [$post($largeBody), strlen($post($largeBody)), true],
	'header_byte_fragments' => [$get, 1, true],
	'oversized_header_1m' => [str_repeat('a', 1048576), 1048576, false]
];
$results = [];
foreach($cases as $name => [$wire, $chunkBytes, $valid]){
	$chunks = str_split($wire, $chunkBytes);
	$run = static function() use ($config, $chunks, $valid) : void{
		$parser = new HttpRequestParser($config);
		foreach($chunks as $chunk){ $parser->feed($chunk); }
		if($valid){
			if($parser->takeRequest() === null || $parser->getBufferedBytes() !== 0){ throw new \RuntimeException('Parser benchmark correctness failure'); }
		}elseif($parser->getState() !== HttpParseState::FAILED || $parser->getBufferedBytes() !== 0){
			throw new \RuntimeException('Parser rejection benchmark correctness failure');
		}
	};
	for($i = 0; $i < 50; ++$i){ $run(); }
	$before = memory_get_usage();
	$start = hrtime(true);
	for($i = 0; $i < $iterations; ++$i){ $run(); }
	$seconds = (hrtime(true) - $start) / 1_000_000_000;
	$retained = memory_get_usage() - $before;
	$results[$name] = ['input_bytes' => strlen($wire), 'chunk_bytes' => $chunkBytes, 'iterations' => $iterations, 'elapsed_ms' => round($seconds * 1000, 3), 'requests_per_second' => round($iterations / $seconds, 1), 'retained_php_bytes' => $retained];
}
echo json_encode(['php' => PHP_VERSION, 'os' => PHP_OS_FAMILY, 'jit' => ini_get('opcache.jit'), 'peak_php_allocated_bytes' => memory_get_peak_usage(true), 'workloads' => $results], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), "\n";
