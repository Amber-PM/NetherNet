<?php

declare(strict_types=1);

namespace amber\nethernet\internal;

final class TransportCleanupException extends \RuntimeException{
	public function __construct(\Throwable $previous){
		parent::__construct('Native peer cleanup failed', 0, $previous);
	}
}
