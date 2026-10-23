<?php

declare(strict_types=1);

namespace amber\nethernet\tests\transport;

use amber\nethernet\Channel;
use amber\nethernet\framing\FrameCodec;
use amber\nethernet\identity\SdpIdentity;
use amber\nethernet\signaling\HttpParseState;
use amber\nethernet\signaling\HttpRequestParser;
use amber\nethernet\TransportConfig;
use amber\nethernet\TransportException;
use PHPUnit\Framework\TestCase;

final class ParserRobustnessTest extends TestCase{
	public function testSeededMalformedHttpIsBoundedAndCannotPoisonAnotherParser() : void{
		$config = new TransportConfig(maxHttpHeaderBytes: 256, maxSdpBytes: 128);
		for($i = 0; $i < 128; ++$i){
			$seed = hash('sha256', 'B1-http-20261015:' . $i, true);
			$parser = new HttpRequestParser($config);
			$wire = "POST /v1/join/id HTTP/1.1\r\nHost: bad\0host\r\nContent-Length: 9999999\r\n\r\n" . str_repeat($seed, 32);
			foreach(str_split($wire, 1 + ord($seed[0]) % 31) as $chunk){
				$parser->feed($chunk);
				self::assertLessThanOrEqual($config->maxHttpHeaderBytes + $config->maxSdpBytes, $parser->getBufferedBytes());
			}
			$parser->eof();
			self::assertSame(HttpParseState::FAILED, $parser->getState());
			self::assertSame(0, $parser->getBufferedBytes());
			self::assertNull($parser->takeRequest());
			$healthy = new HttpRequestParser($config);
			$healthy->feed("GET /v1/join HTTP/1.1\r\nHost: test\r\n\r\n");
			self::assertSame(['networkId' => null, 'body' => ''], $healthy->takeRequest());
		}
	}

	public function testSeededMalformedSdpAlwaysRejectsAndValidInputStillParses() : void{
		$config = new TransportConfig(maxSdpBytes: 512);
		for($i = 0; $i < 128; ++$i){
			$seed = hash('sha256', 'B1-sdp-20261015:' . $i, true);
			$offset = ord($seed[0]) % strlen(FakePeer::SDP);
			$input = substr(FakePeer::SDP, 0, $offset) . "\0" . $seed . substr(FakePeer::SDP, $offset);
			try{ SdpIdentity::fromSdp($input, $config); self::fail('Invalid SDP accepted'); }
			catch(TransportException $e){ self::assertSame('invalid_sdp', $e->errorCode); }
			self::assertSame(FakePeer::SDP, SdpIdentity::fromSdp(FakePeer::SDP, $config)->sdpWithoutIdentity);
		}
	}

	public function testSeededInvalidCountdownSequencesReleaseAssemblyAndRecover() : void{
		$config = new TransportConfig(maxPayloadBytes: 32, maxFragments: 4);
		$codec = new FrameCodec($config);
		for($i = 0; $i < 128; ++$i){
			$seed = hash('sha256', 'B1-frame-20261015:' . $i, true);
			self::assertNull($codec->receive("\2" . substr($seed, 0, 7), Channel::RELIABLE, 8, (float) $i));
			$wrong = chr(2 + ord($seed[0]) % 254) . substr($seed, 1, 1 + ord($seed[1]) % 7);
			try{ $codec->receive($wrong, Channel::RELIABLE, 8, (float) $i); self::fail('Invalid countdown accepted'); }
			catch(TransportException $e){ self::assertSame('framing_invalid', $e->errorCode); }
			self::assertFalse($codec->isAssembling());
			self::assertSame(0, $codec->getBufferedBytes());
			self::assertSame('valid', $codec->receive("\0valid", Channel::RELIABLE, 8, (float) $i));
		}
	}
}
