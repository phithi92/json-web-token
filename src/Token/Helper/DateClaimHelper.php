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

class DateClaimHelper
{
    // DateTimeImmutable object to handle date-related operations
    private readonly DateTimeImmutable $dateTimeImmutable;

    public function __construct(?DateTimeImmutable $dateTime = null)
    {
        $this->dateTimeImmutable = $dateTime ?? new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }

    /**
     * Parses and sets a timestamp field in the JWT payload.
     * Converts a datetime string into a Unix timestamp and stores it under the specified key.
     *
     * @param string     $key      The key for the timestamp field (e.g., "iat", "nbf", "exp").
     * @param string|int $dateTime The datetime string to be converted into a timestamp.
     *
     * @see addClaim()
     *
     * @throws InvalidDateTimeException If the datetime string is in an invalid format.
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     */
    public function setClaimTimestamp(JwtPayload $payload, string $key, string|int $dateTime): void
    {
        $adjustedDateTime = $this->buildValidDateTime($dateTime);

        $payload->addClaim($key, $adjustedDateTime->getTimestamp());
    }

    public function getReferenceTime(): DateTimeImmutable
    {
        return $this->dateTimeImmutable;
    }

    /**
     * Converts a datetime expression or timestamp into a DateTimeImmutable object.
     *
     * @param string|int $dateTime Relative string (e.g. "+5 minutes") or timestamp (string or int)
     *
     * @throws InvalidDateTimeException
     */
    private function buildValidDateTime(string|int $dateTime): DateTimeImmutable
    {
        // Falls Timestamp als int oder int-String
        if (is_int($dateTime) || (ctype_digit($dateTime))) {
            $timestamp = (int) $dateTime;

            try {
                return $this->getReferenceTime()->setTimestamp($timestamp);
            } catch (Throwable $e) {
                throw new InvalidDateTimeException((string) $dateTime);
            }
        }

        // Ansonsten: relative Angabe oder absolute Datumsangabe
        try {
            $adjustedDateTime = @$this->getReferenceTime()->modify($dateTime);
        } catch (Throwable $e) {
            throw new InvalidDateTimeException($dateTime);
        }

        // PHP < 8.3 Fallback-Schutz
        // @phpstan-ignore-next-line
        if (! $adjustedDateTime instanceof DateTimeImmutable) {
            throw new InvalidDateTimeException($dateTime);
        }

        return $adjustedDateTime;
    }
}
