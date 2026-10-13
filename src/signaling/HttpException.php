<?php

declare(strict_types=1);

namespace amber\nethernet\signaling;

final class HttpException extends \RuntimeException{
	public function __construct(public readonly int $status, public readonly ?string $allow = null){
		parent::__construct('HTTP request rejected');
	}
}
