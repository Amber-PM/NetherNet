<?php

declare(strict_types=1);

namespace amber\nethernet;

enum SendResult{
	case ACCEPTED;
	case BACKPRESSURE;
	case DROPPED;
}
