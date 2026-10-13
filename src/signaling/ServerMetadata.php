<?php

declare(strict_types=1);

namespace amber\nethernet\signaling;

final class ServerMetadata{
	public function __construct(
		public readonly string $name,
		public readonly int $protocol,
		public readonly string $version,
		public readonly string $level,
		public readonly int $players,
		public readonly int $maxPlayers,
		public readonly int $gameType
	){
		foreach([$name, $version, $level] as $text){
			if(strlen($text) > 1024 || preg_match('//u', $text) !== 1 || preg_match('/[\x00-\x1f\x7f-\x9f]/u', $text) === 1){
				throw new \InvalidArgumentException('Metadata text must be bounded UTF-8 without controls');
			}
		}
		if($protocol < 0 || $players < 0 || $maxPlayers < 0 || $gameType < 0 || $gameType > 2){
			throw new \InvalidArgumentException('Metadata numbers are outside the server info profile');
		}
	}

	public function toJson() : string{
		return json_encode(get_object_vars($this), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	}
}
