<?php

declare(strict_types=1);

namespace amber\nethernet\signaling;

final class HttpResponse{
	private const REASONS = [
		200 => 'OK', 400 => 'Bad Request', 403 => 'Forbidden', 404 => 'Not Found',
		405 => 'Method Not Allowed', 408 => 'Request Timeout', 411 => 'Length Required',
		413 => 'Content Too Large', 414 => 'URI Too Long', 415 => 'Unsupported Media Type',
		417 => 'Expectation Failed', 431 => 'Request Header Fields Too Large',
		500 => 'Internal Server Error', 501 => 'Not Implemented',
		503 => 'Service Unavailable', 504 => 'Gateway Timeout'
	];

	public function __construct(
		public readonly int $status,
		public readonly string $body = '',
		public readonly string $contentType = 'text/plain; charset=utf-8',
		public readonly ?string $allow = null
	){
		if(!isset(self::REASONS[$status]) || !in_array($contentType, ['application/json', 'application/sdp', 'text/plain; charset=utf-8'], true) ||
			($allow !== null && ($status !== 405 || !in_array($allow, ['GET', 'POST'], true))) || ($status === 405 && $allow === null)){
			throw new \InvalidArgumentException('Unsupported HTTP response profile');
		}
	}

	public static function error(int $status, ?string $allow = null) : self{
		if($status === 200 || !isset(self::REASONS[$status])){ throw new \InvalidArgumentException('Unsupported error status'); }
		return new self($status, self::REASONS[$status], allow: $allow);
	}

	public function encode() : string{
		$head = 'HTTP/1.1 ' . $this->status . ' ' . self::REASONS[$this->status] . "\r\n" .
			'Content-Type: ' . $this->contentType . "\r\nContent-Length: " . strlen($this->body) .
			"\r\nConnection: close\r\nCache-Control: no-store\r\n";
		if($this->allow !== null){ $head .= 'Allow: ' . $this->allow . "\r\n"; }
		return $head . "\r\n" . $this->body;
	}
}
