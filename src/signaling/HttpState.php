<?php

declare(strict_types=1);

namespace amber\nethernet\signaling;

enum HttpState{
	case HEADERS;
	case BODY;
	case PENDING;
	case RESPONSE;
	case WRITING;
	case CLOSED;
}
