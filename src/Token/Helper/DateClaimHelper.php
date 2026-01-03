<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Helper;

use DateMalformedStringException;
use DateTimeImmutable;
use Exception;
use Phithi92\JsonWebToken\Exceptions\Payload\EmptyFieldException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidDateTimeException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidValueTypeException;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Throwable;

use function is_int;
use function preg_match;

/**
 * Helper to convert date expressions into Unix timestamps for JWT claims.
 * All calculations are based on a UTC reference time.
 */
final class DateClaimHelper
{
    /**
     * Standardized time-based claims (NumericDate) as defined in RFC 7519
     * and OpenID Connect (OIDC). All of them must be treated as timestamps
     * and must never be retained from previous tokens when reissuing.
     */
    public const TIME_CLAIMS = ['exp', 'nbf', 'iat', 'auth_time'];

    /** Reference time used for relative calculations (UTC). */
    private readonly DateTimeImmutable $dateTimeImmutable;

    /**
     * @param DateTimeImmutable|null $dateTime optional reference time; defaults to now (UTC)
     */
    public function __construct(?DateTimeImmutable $dateTime = null)
    {
        $this->dateTimeImmutable = $dateTime ?? (new UtcClock())->now();
    }

    /**
     * Set a timestamp claim (iat/nbf/exp) from a date expression or timestamp.
     *
     * @param string     $key      Claim name (e.g., "iat", "nbf", "exp").
     * @param string|int $dateTime Relative/absolute datetime (e.g., "+5 minutes", "2025-08-16 12:00")
     *                             or Unix timestamp.
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
     * PHPStan workaround: DateTimeImmutable throws different exception types
     * depending on the PHP version.
     *
     * @throws DateMalformedStringException PHP 8.3+
     * @throws Exception                    Prior to PHP 8.3
     */
    public function buildDate(DateTimeImmutable $ref, string $dateTime): DateTimeImmutable
    {
        $result = @$ref->modify($dateTime);
        if (! $result instanceof DateTimeImmutable) {
            // Convert failure to a consistent exception for PHPStan (and runtime)
            throw new Exception("Invalid date modification string: {$dateTime}");
        }

        return $result;
    }

    public function getNowInReferenceTimezone(): DateTimeImmutable
    {
        $timezone = $this->dateTimeImmutable->getTimezone();

        return new DateTimeImmutable('now', $timezone);
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

        try {
            $adjustedDateTime = $this->buildDate($ref, $dateTime);
        } catch (Throwable) {
            throw new InvalidDateTimeException($dateTime);
        }

        self::assertDateTimeImmutable($adjustedDateTime, $dateTime);

        return $adjustedDateTime;
    }

    /**
     * Ensures the value is a DateTimeImmutable; otherwise throws.
     *
     * @param DateTimeImmutable|false|null $value result of DateTimeImmutable::modify() on older PHP versions
     * @param string|int                   $input original input for error context
     *
     * @throws InvalidDateTimeException
     */
    private static function assertDateTimeImmutable(
        DateTimeImmutable|false|null $value,
        string|int $input,
    ): DateTimeImmutable {
        if (! $value instanceof DateTimeImmutable) {
            throw new InvalidDateTimeException((string) $input);
        }

        return $value;
    }
}
