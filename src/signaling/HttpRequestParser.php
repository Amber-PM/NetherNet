<?php

declare(strict_types=1);

namespace amber\nethernet\signaling;

use amber\nethernet\TransportConfig;

final class HttpRequestParser{
	private HttpParseState $state = HttpParseState::HEADERS;
	private string $head = '';
	private string $body = '';
	private ?string $networkId = null;
	private int $length = 0;
	private ?HttpException $error = null;

	public function __construct(private readonly TransportConfig $config){}

	public function getState() : HttpParseState{ return $this->state; }
	public function getError() : ?HttpException{ return $this->error; }
	public function getBufferedBytes() : int{ return strlen($this->head) + strlen($this->body); }

	public function feed(string $bytes) : void{
		if($bytes === '' || $this->state === HttpParseState::FAILED){ return; }
		try{
			$offset = 0;
			$size = strlen($bytes);
			while($offset < $size && $this->state === HttpParseState::HEADERS){
				if(strlen($this->head) >= $this->config->maxHttpHeaderBytes){ throw new HttpException(431); }
				$byte = $bytes[$offset++];
				$previous = $this->head === '' ? '' : $this->head[strlen($this->head) - 1];
				if(($byte === "\n" && $previous !== "\r") || ($previous === "\r" && $byte !== "\n") ||
					(ord($byte) < 32 && !in_array($byte, ["\t", "\r", "\n"], true)) || ord($byte) > 126){
					throw new HttpException(400);
				}
				$this->head .= $byte;
				if(str_ends_with($this->head, "\r\n\r\n")){
					$this->parseHead();
					$this->head = '';
					$this->state = $this->length === 0 ? HttpParseState::COMPLETE : HttpParseState::BODY;
				}
			}
			if($offset < $size){
				if($this->state !== HttpParseState::BODY || $size - $offset > $this->length - strlen($this->body)){
					throw new HttpException(400);
				}
				$this->body .= substr($bytes, $offset);
				if(strlen($this->body) === $this->length){ $this->state = HttpParseState::COMPLETE; }
			}
		}catch(HttpException $e){
			$this->fail($e);
		}
	}

	public function eof() : void{
		if($this->state === HttpParseState::HEADERS || $this->state === HttpParseState::BODY){ $this->fail(new HttpException(400)); }
	}

	/** @return array{networkId: ?string, body: string}|null */
	public function takeRequest() : ?array{
		if($this->state !== HttpParseState::COMPLETE){ return null; }
		$request = ['networkId' => $this->networkId, 'body' => $this->body];
		$this->head = $this->body = '';
		$this->networkId = null;
		$this->state = HttpParseState::CONSUMED;
		return $request;
	}

	private function fail(HttpException $error) : void{
		$this->error = $error;
		$this->head = $this->body = '';
		$this->networkId = null;
		$this->state = HttpParseState::FAILED;
	}

	private function parseHead() : void{
		$lines = explode("\r\n", substr($this->head, 0, -4));
		if(preg_match("~^([!#$%&'*+.^_`|\\~0-9A-Za-z-]+) (/[^ ]*) HTTP/1\\.1$~D", array_shift($lines), $match) !== 1){
			throw new HttpException(400);
		}
		/** @var array<string, string> $headers */
		$headers = [];
		$critical = ['host', 'content-length', 'transfer-encoding', 'content-type', 'content-encoding', 'expect', 'connection', 'upgrade', 'trailer'];
		foreach($lines as $line){
			if(preg_match("~^([!#$%&'*+.^_`|\\~0-9A-Za-z-]+):([\\t\\x20-\\x7e]*)$~D", $line, $parts) !== 1){ throw new HttpException(400); }
			$name = strtolower($parts[1]);
			if(in_array($name, $critical, true)){
				if(isset($headers[$name])){ throw new HttpException(400); }
				$headers[$name] = trim($parts[2], " \t");
			}
		}
		$host = $headers['host'] ?? '';
		if(preg_match('/^(?:[A-Za-z0-9._-]+|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?$/D', $host) !== 1){ throw new HttpException(400); }
		if(isset($headers['transfer-encoding'])){ throw new HttpException(isset($headers['content-length']) ? 400 : 501); }
		if(isset($headers['expect'])){ throw new HttpException(417); }
		if(isset($headers['content-encoding'])){ throw new HttpException(415); }
		if(isset($headers['upgrade']) || isset($headers['trailer'])){ throw new HttpException(400); }
		if(isset($headers['connection'])){
			foreach(explode(',', $headers['connection']) as $option){
				if(!in_array(strtolower(trim($option, " \t")), ['close', 'keep-alive'], true)){ throw new HttpException(400); }
			}
		}
		$path = $match[2];
		if(preg_match('/[\\\\?#\x00-\x20\x7f]/', $path) === 1){ throw new HttpException(400); }
		if($path === '/v1/join'){
			if($match[1] !== 'GET'){ throw new HttpException(405, 'GET'); }
		}elseif(str_starts_with($path, '/v1/join/')){
			$this->networkId = $this->decodeNetworkId(substr($path, 9));
			if($match[1] !== 'POST'){ throw new HttpException(405, 'POST'); }
			if(preg_match('/^application\/sdp(?:[ \t]*;[ \t]*charset=(?:utf-8|"utf-8"))?$/iD', $headers['content-type'] ?? '') !== 1){
				throw new HttpException(415);
			}
			if(!isset($headers['content-length'])){ throw new HttpException(411); }
		}else{
			throw new HttpException(404);
		}
		if(isset($headers['content-length'])){
			$value = $headers['content-length'];
			if(preg_match('/^[0-9]+$/D', $value) !== 1){ throw new HttpException(400); }
			$value = ltrim($value, '0');
			$max = (string) $this->config->maxSdpBytes;
			// compare before converting client integers
			if(strlen($value) > strlen($max) || (strlen($value) === strlen($max) && strcmp($value, $max) > 0)){ throw new HttpException(413); }
			$this->length = $value === '' ? 0 : (int) $value;
		}
		if(($this->networkId === null && $this->length !== 0) || ($this->networkId !== null && $this->length === 0)){ throw new HttpException(400); }
	}

	private function decodeNetworkId(string $segment) : string{
		if($segment === '' || preg_match("~^(?:[A-Za-z0-9._!$&'()*+,;=:@\\~-]|%[A-Fa-f0-9]{2})+$~D", $segment) !== 1){
			throw new HttpException(400);
		}
		$id = rawurldecode($segment);
		if(strlen($id) > $this->config->maxNetworkIdBytes){ throw new HttpException(414); }
		if(preg_match('//u', $id) !== 1 || preg_match('/[\x00-\x20\x7f-\x9f\\\\\/%?#]/u', $id) === 1 || $id === '.' || $id === '..'){
			throw new HttpException(400);
		}
		return $id;
	}
}
