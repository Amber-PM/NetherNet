<?php

declare(strict_types=1);

if(!extension_loaded('webrtc')){
	throw new RuntimeException('Native tests require a loaded ext-webrtc; skipping is forbidden');
}
require dirname(__DIR__, 2) . '/vendor/autoload.php';
