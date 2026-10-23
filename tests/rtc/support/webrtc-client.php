<?php

declare(strict_types=1);

use amber\nethernet\backend\ExtWebRtcPeer;
use amber\nethernet\Channel;
use amber\nethernet\framing\FrameCodec;
use amber\nethernet\TransportConfig;

// runs in its own process with ext-webrtc only
require dirname(__DIR__, 3) . '/vendor/autoload.php';
if(extension_loaded('rtc')){
	fwrite(STDERR, "ext-rtc must not be loaded here\n");
	exit(1);
}

/** @param \Closure(): bool $condition */
function waitUntil(\Closure $condition) : void{
	$deadline = hrtime(true) + 10_000_000_000;
	while(!$condition()){
		if(hrtime(true) >= $deadline){ throw new RuntimeException('client wait timed out'); }
		usleep(1000);
	}
}

function command(string $expected) : string{
	$line = fgets(STDIN);
	if($line === false || !str_starts_with($line, $expected)){ throw new RuntimeException('unexpected command'); }
	return trim(substr($line, strlen($expected)));
}

function reply(string $line) : void{
	fwrite(STDOUT, $line . "\n");
	fflush(STDOUT);
}

$config = new TransportConfig(maxMessageBytes: 512);
$codec = new FrameCodec($config);
$client = new ExtWebRtcPeer($config);
try{
	$client->createChannel(Channel::RELIABLE);
	$client->createChannel(Channel::UNRELIABLE);
	waitUntil(fn() => $client->isGatheringComplete());
	reply('OFFER ' . bin2hex($client->getLocalDescription() ?? throw new RuntimeException('missing offer')));
	$answer = hex2bin(command('ANSWER '));
	if($answer === false){ throw new RuntimeException('invalid answer'); }
	$client->setRemoteAnswer($answer);
	waitUntil(fn() => $client->getState() === 'CONNECTED' && $client->isChannelOpen(Channel::RELIABLE) && $client->isChannelOpen(Channel::UNRELIABLE));
	reply('OPEN ' . ($client->getRemoteFingerprint() ?? ''));
	$payload = hex2bin(command('SEND '));
	if($payload === false){ throw new RuntimeException('invalid payload'); }
	foreach($codec->encode($payload, $client->getMessageCapacity(Channel::RELIABLE)) as $frame){
		if(!$client->sendFrame(Channel::RELIABLE, $frame)){ throw new RuntimeException('client backpressure'); }
	}
	if(!$client->sendFrame(Channel::UNRELIABLE, "\0" . substr($payload, 0, 64))){ throw new RuntimeException('client unreliable drop'); }
	reply('SENT');
	$reliable = null;
	$unreliable = null;
	waitUntil(function() use ($client, $codec, &$reliable, &$unreliable) : bool{
		while($reliable === null && ($frame = $client->receiveFrame(Channel::RELIABLE)) !== null){
			$reliable = $codec->receive($frame, Channel::RELIABLE, 512, hrtime(true) / 1_000_000_000);
		}
		$unreliable ??= $client->receiveFrame(Channel::UNRELIABLE);
		return $reliable !== null && $unreliable !== null;
	});
	reply('RECEIVED ' . bin2hex((string) $reliable) . ' ' . bin2hex((string) $unreliable));
	command('CLOSE');
	$client->close();
	reply('CLOSED');
}catch(\Throwable $e){
	reply('ERROR ' . get_class($e) . ' ' . $e->getMessage());
	$client->close();
	exit(1);
}
