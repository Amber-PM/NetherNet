<?php

declare(strict_types=1);

namespace amber\nethernet\tests\framing;

use amber\nethernet\Channel;
use amber\nethernet\TransportConfig;
use amber\nethernet\TransportException;
use amber\nethernet\framing\FrameCodec;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class FrameCodecTest extends TestCase{
	public function testReliableGoldenFragmentsPreserveBinaryBytes() : void{
		$codec = new FrameCodec(new TransportConfig());
		self::assertSame(["\x02ab", "\x01\0c", "\x00d"], iterator_to_array($codec->encode("ab\0cd", 3)));
		self::assertNull($codec->receive("\x02ab", Channel::RELIABLE, 3, 1.0));
		self::assertSame(2, $codec->getBufferedBytes());
		self::assertTrue($codec->isAssembling());
		self::assertNull($codec->receive("\x01\0c", Channel::RELIABLE, 3, 2.0));
		self::assertSame("ab\0cd", $codec->receive("\x00d", Channel::RELIABLE, 3, 3.0));
		self::assertFalse($codec->isAssembling());
		self::assertSame(0, $codec->getBufferedBytes());
	}

	public function testEmptyAndExactCapacityMessages() : void{
		$codec = new FrameCodec(new TransportConfig());
		self::assertSame(["\0"], iterator_to_array($codec->encode('', 3)));
		self::assertSame(["\0ab"], iterator_to_array($codec->encode('ab', 3)));
		self::assertSame('', $codec->receive("\0", Channel::RELIABLE, 3, 0.0));
		self::assertSame("\0ab", $codec->encodeUnreliable('ab', 3));
		self::assertNull($codec->encodeUnreliable('abc', 3));
	}

	public function testUnreliableCannotAlterReliableAssembly() : void{
		$codec = new FrameCodec(new TransportConfig());
		$codec->receive("\1a", Channel::RELIABLE, 3, 0.0);
		self::assertSame('x', $codec->receive("\0x", Channel::UNRELIABLE, 3, 1.0));
		self::assertSame('ab', $codec->receive("\0b", Channel::RELIABLE, 3, 2.0));
	}

	public function testMaximumCountdownIsUnsigned() : void{
		$codec = new FrameCodec(new TransportConfig());
		$frames = iterator_to_array($codec->encode(str_repeat('a', 256), 2));
		self::assertCount(256, $frames);
		self::assertSame("\xffa", $frames[0]);
		self::assertSame("\0a", $frames[255]);
		foreach($frames as $frame){ $result = $codec->receive($frame, Channel::RELIABLE, 2, 0.0); }
		self::assertSame(str_repeat('a', 256), $result);
	}

	/** @return iterable<string, array{string, Channel, int, ?string}> */
	public static function malformedFrames() : iterable{
		yield 'missing header' => ['', Channel::RELIABLE, 3, null];
		yield 'oversize SCTP frame' => ["\0abc", Channel::RELIABLE, 3, null];
		yield 'unreliable fragment' => ["\1a", Channel::UNRELIABLE, 3, null];
		yield 'empty initial fragment' => ["\1", Channel::RELIABLE, 3, null];
		yield 'missing middle fragment' => ["\0b", Channel::RELIABLE, 3, "\2a"];
		yield 'repeated countdown' => ["\2b", Channel::RELIABLE, 3, "\2a"];
		yield 'new fragmented message interleaves' => ["\3b", Channel::RELIABLE, 3, "\2a"];
		yield 'empty final fragment' => ["\0", Channel::RELIABLE, 3, "\1a"];
	}

	#[DataProvider('malformedFrames')]
	public function testMalformedInputClearsAssembly(string $frame, Channel $channel, int $capacity, ?string $first) : void{
		$codec = new FrameCodec(new TransportConfig());
		if($first !== null){ $codec->receive($first, Channel::RELIABLE, $capacity, 0.0); }
		try{
			$codec->receive($frame, $channel, $capacity, 1.0);
			self::fail('Malformed frame accepted');
		}catch(TransportException $e){
			self::assertSame('framing_invalid', $e->errorCode);
		}
		self::assertFalse($codec->isAssembling());
		self::assertSame(0, $codec->getBufferedBytes());
	}

	public function testAssemblyTimeoutIsAbsoluteAndResetsState() : void{
		$codec = new FrameCodec(new TransportConfig());
		$codec->receive("\2a", Channel::RELIABLE, 3, 0.0);
		$codec->receive("\1b", Channel::RELIABLE, 3, 9.0);
		try{
			$codec->expire(10.0);
			self::fail('Timed out assembly retained');
		}catch(TransportException $e){ self::assertSame('framing_invalid', $e->errorCode); }
		self::assertSame('z', $codec->receive("\0z", Channel::RELIABLE, 3, 10.0));
	}

	public function testReceiveCannotCompleteAfterDeadline() : void{
		$codec = new FrameCodec(new TransportConfig());
		$codec->receive("\1a", Channel::RELIABLE, 3, 0.0);
		$this->expectException(TransportException::class);
		$codec->receive("\0b", Channel::RELIABLE, 3, 10.0);
	}

	public function testPayloadAndFragmentLimitsAreCheckedBeforeEncoding() : void{
		$codec = new FrameCodec(new TransportConfig(maxPayloadBytes: 4, maxFragments: 2));
		self::assertSame(["\1ab", "\0cd"], iterator_to_array($codec->encode('abcd', 3)));
		$this->expectException(TransportException::class);
		$codec->encode('abcde', 10);
	}

	public function testTooManyOutgoingFragments() : void{
		$codec = new FrameCodec(new TransportConfig(maxFragments: 2));
		$this->expectException(TransportException::class);
		$codec->encode('abc', 2);
	}

	public function testTooManyIncomingFragments() : void{
		$codec = new FrameCodec(new TransportConfig(maxFragments: 2));
		$this->expectException(TransportException::class);
		$codec->receive("\2a", Channel::RELIABLE, 3, 0.0);
	}

	public function testCumulativeReceiveLimit() : void{
		$codec = new FrameCodec(new TransportConfig(maxPayloadBytes: 3));
		$codec->receive("\1ab", Channel::RELIABLE, 3, 0.0);
		try{
			$codec->receive("\0cd", Channel::RELIABLE, 3, 1.0);
			self::fail('Assembly exceeded limit');
		}catch(TransportException $e){ self::assertSame('payload_too_large', $e->errorCode); }
		self::assertSame(0, $codec->getBufferedBytes());
	}

	/** @return iterable<array{int}> */
	public static function invalidCapacities() : iterable{
		yield [0]; yield [1]; yield [262145];
	}
	#[DataProvider('invalidCapacities')]
	public function testInvalidNegotiatedCapacity(int $capacity) : void{
		$codec = new FrameCodec(new TransportConfig());
		$this->expectException(\InvalidArgumentException::class);
		$codec->encode('a', $capacity);
	}

	/** @return iterable<array{float}> */
	public static function invalidTimes() : iterable{
		yield [-1.0]; yield [INF]; yield [NAN];
	}
	#[DataProvider('invalidTimes')]
	public function testInvalidClock(float $now) : void{
		$codec = new FrameCodec(new TransportConfig());
		$this->expectException(\InvalidArgumentException::class);
		$codec->expire($now);
	}

	public function testClockCannotMoveBackwards() : void{
		$codec = new FrameCodec(new TransportConfig());
		$codec->expire(2.0);
		$this->expectException(\InvalidArgumentException::class);
		$codec->expire(1.0);
	}

	public function testExplicitResetDiscardsIncompleteMessage() : void{
		$codec = new FrameCodec(new TransportConfig());
		$codec->receive("\1a", Channel::RELIABLE, 3, 0.0);
		$codec->reset();
		self::assertSame('b', $codec->receive("\0b", Channel::RELIABLE, 3, 1.0));
	}
}
