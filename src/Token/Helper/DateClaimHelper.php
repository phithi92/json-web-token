<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Helper;

use DateTimeImmutable;
use DateTimeZone;
use Phithi92\JsonWebToken\Exceptions\Payload\EmptyFieldException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidDateTimeException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidValueTypeException;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Throwable;

/**
 * Helper to convert date expressions into Unix timestamps for JWT claims.
 * All calculations are based on a UTC reference time.
 */
class DateClaimHelper
{
    /** Reference time used for relative calculations (UTC). */
    private readonly DateTimeImmutable $dateTimeImmutable;

    /**
     * @param DateTimeImmutable|null $dateTime Optional reference time; defaults to now (UTC).
     */
    public function __construct(?DateTimeImmutable $dateTime = null)
    {
        $this->dateTimeImmutable = $dateTime ?? $this->createReferenceTime();
    }

    /**
     * Set a timestamp claim (iat/nbf/exp) from a date expression or timestamp.
     *
     * @param string      $key       Claim name (e.g., "iat", "nbf", "exp").
     * @param string|int  $dateTime  Relative/absolute datetime (e.g., "+5 minutes", "2025-08-16 12:00") or Unix timestamp.
     *
     * @throws InvalidDateTimeException
     * @throws InvalidValueTypeException
     * @throws EmptyFieldException
     *
     * @see JwtPayload::addClaim()
     */
    public function setClaimTimestamp(JwtPayload $payload, string $key, string|int $dateTime): void
    {
        $payload->addClaim($key, $this->toTimestamp($dateTime));
    }

    /** Returns the reference time used for calculations. */
    public function getReferenceTime(): DateTimeImmutable
    {
        return $this->dateTimeImmutable;
    }

    public function toTimestamp(string|int $input): int
    {
        return $this->buildValidDateTime($input)->getTimestamp();
    }

    /**
     * Normalize a date expression or timestamp to a DateTimeImmutable anchored to the reference time.
     *
     * @throws InvalidDateTimeException
     */
    private function buildValidDateTime(string|int $dateTime): DateTimeImmutable
    {
        $ref = $this->getReferenceTime();

        // Numeric input: treat as Unix timestamp.
        if (is_int($dateTime) || preg_match('/^-?\d+$/', $dateTime) === 1) {
            $timestamp = (int) $dateTime;

            try {
                return $ref->setTimestamp($timestamp);
            } catch (Throwable) {
                throw new InvalidDateTimeException((string) $dateTime);
            }
        }

        // Relative or absolute string: derive from the reference time.
        try {
            $adjustedDateTime = @$ref->modify($dateTime);
        } catch (Throwable) {
            throw new InvalidDateTimeException($dateTime);
        }

        self::assertDateTimeImmutable($adjustedDateTime, $dateTime);

        return $adjustedDateTime;
    }

    /**
     * Ensures the value is a DateTimeImmutable; otherwise throws.
     *
     * @param DateTimeImmutable|false|null $value Result of DateTimeImmutable::modify() on older PHP versions.
     * @param string|int                   $input Original input for error context.
     *
     * @throws InvalidDateTimeException
     */
    private static function assertDateTimeImmutable(DateTimeImmutable|false|null $value, string|int $input): DateTimeImmutable
    {
        if (! $value instanceof DateTimeImmutable) {
            throw new InvalidDateTimeException((string) $input);
        }

        return $value;
    }

    /** Create the default UTC reference time. */
    private function createReferenceTime(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }
}
