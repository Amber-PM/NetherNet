<?php

declare(strict_types=1);

namespace amber\nethernet\internal;

use amber\nethernet\TransportConfig;

final class TransportBudget{
	private int $reserved = 0;
	private int $messages = 0;
	private int $bytes = 0;
	private int $generation = 0;
	public function __construct(private readonly TransportConfig $config){}

	public function reserve(int $bytes) : bool{
		if($bytes < 0 || $bytes > $this->config->maxAggregateBytes - $this->reserved){ return false; }
		$this->reserved += $bytes;
		return true;
	}

	public function release(int $bytes) : void{
		if($bytes < 0 || $bytes > $this->reserved){ throw new \LogicException('Invalid transport memory release'); }
		$this->reserved -= $bytes;
	}

	public function resetWork() : void{
		if($this->generation === PHP_INT_MAX){ throw new \LogicException('Transport poll generation exhausted'); }
		++$this->generation;
		$this->messages = 0;
		$this->bytes = 0;
	}
	public function getGeneration() : int{ return $this->generation; }
	public function canWork(int $bytes) : bool{
		return $bytes >= 0 && $this->messages < $this->config->globalPollMessages && $bytes <= $this->config->globalPollBytes - $this->bytes;
	}
	public function consume(int $bytes) : void{
		if(!$this->canWork($bytes)){ throw new \LogicException('Transport work budget exceeded'); }
		++$this->messages;
		$this->bytes += $bytes;
	}
}
