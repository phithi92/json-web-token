<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Helper;

use DateTimeImmutable;
use DateTimeZone;

use function time;

/**
 * Provides UTC time functionality for JWT operations.
 *
 * Offers both instance-based and static methods for obtaining current UTC time.
 * Static methods are more efficient when only occasional time access is needed,
 * while instance methods are preferred for repeated operations.
 */
final class UtcClock
{
    private const TIMEZONE_NAME = 'UTC';

    private const DATETIME = 'now';

    /**
     * Static method to get the current UTC time as an immutable datetime object.
     *
     * More efficient than instance methods when only occasional time access is needed.
     *
     * @return DateTimeImmutable Current UTC time
     */
    public static function nowStatic(): DateTimeImmutable
    {
        $tz = new DateTimeZone(self::TIMEZONE_NAME);
        return new DateTimeImmutable(self::DATETIME, $tz);
    }

    /**
     * Static method to get the current UTC time as a Unix timestamp.
     *
     * More efficient than instance methods when only occasional time access is needed.
     *
     * @return int Seconds since the Unix epoch (1970-01-01 00:00:00 UTC).
     */
    public static function nowTimestampStatic(): int
    {
        return time();
    }
}
