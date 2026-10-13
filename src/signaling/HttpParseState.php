<?php

declare(strict_types=1);

namespace amber\nethernet\signaling;

enum HttpParseState{
	case HEADERS;
	case BODY;
	case COMPLETE;
	case CONSUMED;
	case FAILED;
}
