<?php

declare(strict_types=1);

namespace amber\nethernet;

enum ConnectionState{
	case VERIFYING;
	case GATHERING;
	case CONNECTING;
	case OPEN;
	case CLOSING;
	case CLOSED;
}
