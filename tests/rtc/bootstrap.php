<?php

declare(strict_types=1);

if(!extension_loaded('rtc')){
	throw new RuntimeException('ext-rtc tests require a loaded ext-rtc; skipping is forbidden');
}
// both link libdatachannel.so.0.24, coexistence is not certified
if(extension_loaded('webrtc')){
	throw new RuntimeException('ext-rtc tests must not load ext-webrtc in the same process');
}
require dirname(__DIR__, 2) . '/vendor/autoload.php';
