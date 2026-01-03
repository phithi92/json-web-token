<?php

namespace Phithi92\JsonWebToken\Token\Helper;

use DateTimeImmutable;
use DateTimeZone;

final class UtcClock
{
    private DateTimeZone $tz;

    public function __construct()
    {
        $this->tz = new DateTimeZone('UTC');
    }

    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', $this->tz);
    }
}
