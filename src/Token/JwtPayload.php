<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token;

use DateMalformedStringException;
use DateTimeImmutable;
use Exception;
use Phithi92\JsonWebToken\Exceptions\Json\JsonException;
use Phithi92\JsonWebToken\Exceptions\Payload\EmptyFieldException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidDateTimeException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidKeyTypeException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidValueTypeException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;

/**
 * JwtPayload represents the payload segment of a JSON Web Token (JWT).
 *
 * This class manages the creation, validation, and manipulation of JWT payload data.
 * It supports setting standard JWT claims (e.g., "iss", "aud", "iat", "exp", "nbf")
 * and allows custom claims to be added as well. Temporal claims, such as "iat", "nbf",
 * and "exp," are managed with DateTimeImmutable to ensure consistency in date-related
 * operations.
 */
class JwtPayload
{
    private const DECODE_JSON_DEPTH = 5;
    private string $encryptedPayload;

    /** @var array<string, mixed> */
    private array $payload;

    // DateTimeImmutable object to handle date-related operations
    private readonly DateTimeImmutable $dateTimeImmutable;

    /**
     * Constructor initializes the DateTimeImmutable object.
     * The DateTimeImmutable instance will be used for managing date-related claims (e.g., "iat", "nbf", "exp").
     */
    public function __construct(?DateTimeImmutable $dateTime = null)
    {
        $this->dateTimeImmutable = ($dateTime ?? new DateTimeImmutable());
    }

    public function getReferenceTime(): DateTimeImmutable
    {
        return $this->dateTimeImmutable;
    }

    /**
     * Creates a new instance of JwtPayload from a JSON string.
     * This static method parses the JSON input and populates the payload fields accordingly.
     *
     * @param string $json A JSON-encoded string representing the JWT payload data.
     *
     * @uses JsonEncoder Encodes the array representation of the object into JSON.
     *
     * @see fromArray()
     *
     * @return self Returns an instance of JwtPayload with fields populated from the JSON data.
     */
    public function fromJson(string $json): self
    {
        // Decode the JSON string into an associative array
        try {
            /**
             * @var array<string, string|int|float|bool|array<string, mixed>|null> $payload
             */
            $payload = JsonEncoder::decode($json, true, 0, self::DECODE_JSON_DEPTH);
        } catch (JsonException $e) {
            throw new InvalidFormatException('Payload decoding failed: ' . $e->getMessage());
        }

        return self::fromArray($payload);
    }

    /**
     * Populates the current JwtPayload instance from an associative array.
     *
     * This method updates the current instance with key-value pairs from the provided
     * array. Special handling is applied to standard JWT claims (`exp`, `nbf`, `iat`):
     *
     * @param array<mixed> $data The value being checked.
     *
     * @return self The current JwtPayload instance with updated payload data.
     *
     * @throws InvalidValueTypeException If `exp`, `nbf`, or `iat` has an unsupported value type.
     */
    public function fromArray(array $data): self
    {
        // Iterate over the decoded data and set each key-value pair in the payload
        foreach ($data as $key => $value) {
            $this->ensureValidClaim($key, $value);

            if (in_array($key, ['exp', 'nbf', 'iat'], true)) {
                if (is_string($value)) {
                    $this->setClaim($key, $value, true);
                } elseif (is_int($value)) {
                    $this->setClaimTimestamp($key, $value);
                } else {
                    throw new InvalidValueTypeException($key, gettype($value));
                }
            } else {
                $this->setClaim($key, $value);
            }
        }

        return $this;
    }

    /**
     * Converts the token data (JWT payload) into an array.
     *
     * @see validate() Called to ensure the payload meets required criteria.
     * @see setField()
     * @see getField()
     *
     * @return array<string,mixed>
     *         The complete JWT payload as an associative array.
     *
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     */
    public function toArray(): array
    {
        if ($this->getClaim('iat') === null) {
            $this->setClaimTimestamp('iat', 'now');
        }

        return $this->payload;
    }

    /**
     * Serializes the JWT payload data to a JSON-encoded string.
     *
     * Converts the payload properties to an array using `toArray`, then encodes them
     * as a JSON string suitable for inclusion in a JWT.
     *
     * @uses JsonEncoder Encodes the array representation of the object into JSON.
     *
     * @see toArray()
     *
     * @return string The JSON-encoded representation of the JWT payload.
     */
    public function toJson(): string
    {
        $options = (JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        return JsonEncoder::encode($this->toArray(), $options, self::DECODE_JSON_DEPTH);
    }

    /**
     * Adds a field to the token data (JWT payload).
     * Ensures that the key is unique and the value is a valid type (scalar or array).
     *
     * @param string $key The key of the field to add.
     * @param mixed $value A JSON-serializable value
     *
     * @return self Returns the instance to allow method chaining.
     *
     * @throws InvalidValueTypeException if the value type is invalid.
     * @throws EmptyFieldException if the value is empty.
     */
    public function addClaim(string $key, mixed $value): self
    {
        return $this->setClaim($key, $value, false);
    }

    /**
     * Retrieves a specific field from the token data (JWT payload).
     *
     * @param string $claim The field to retrieve.
     */
    public function getClaim(string $claim): mixed
    {
        return $this->payload[$claim] ?? null;
    }

    /**
     * Sets the "iss" (issuer) claim in the JWT payload.
     *
     * @param string $issuer The issuer of the JWT.
     *
     * @see addClaim()
     *
     * @return self Returns the instance to allow method chaining.
     *
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     */
    public function setIssuer(string $issuer): self
    {
        return $this->addClaim('iss', $issuer);
    }

    /**
     * Retrieves the issuer identifier from the payload.
     *
     * This method fetches the value associated with the 'iss' (issuer) field
     * in the payload. The 'iss' field is expected to contain a string identifying
     * the issuer, or null if the field is not set.
     *
     * @see getField()
     *
     * @return string|null The issuer identifier as a string, or null if it is not present.
     */
    public function getIssuer(): ?string
    {
        $issuer = $this->getClaim('iss');
        return is_string($issuer) ? $issuer : null;
    }

    /**
     * Sets the "aud" (audience) claim in the JWT payload.
     *
     * @param array<string, array<string,string>|int|string|null>|string $audience The
     *        intended audience of the JWT. Can be a string or an array of strings.
     *
     * @see addClaim()
     *
     * @return self Returns the instance to allow method chaining.
     *
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     */
    public function setAudience(string|array $audience): self
    {
        return $this->addClaim('aud', $audience);
    }

    /**
     * Retrieves the audience information from the payload.
     *
     * This method fetches the value associated with the 'aud' (audience) field
     * in the payload. The 'aud' field is expected to contain a string identifying
     * the intended audience, or null if the field is not set.
     *
     * @see getField()
     *
     * @return array<mixed>|string|null The audience identifier as a string, or null if it is not present.
     */
    public function getAudience(): string|array|null
    {
        $audience = $this->getClaim('aud');
        return is_string($audience) || is_array($audience) ? $audience : null;
    }

    /**
     * Sets the "iat" (issued at) claim in the JWT payload.
     *
     * @param string $dateTime The issued at time, which will be parsed and stored as a Unix timestamp.
     *
     * @return self Returns the instance to allow method chaining.
     *
     * @see setTimestamp()
     *
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     */
    public function setIssuedAt(string $dateTime): self
    {
        return $this->setClaimTimestamp('iat', $dateTime);
    }

    /**
     * Retrieves the issued-at timestamp from the payload.
     *
     * This method fetches the value associated with the 'iat' (issued-at) field
     * in the payload. The 'iat' field is expected to contain a string representing
     * a timestamp, or null if the field is not set.
     *
     * @see getField()
     *
     * @return int|null The issued-at timestamp as a string, or null if it is not present.
     */
    public function getIssuedAt(): int|null
    {
        $issued = $this->getClaim('iat');
        $resolvedIssued = is_int($issued) ? $issued : 0;
        return $resolvedIssued > 0 ? $resolvedIssued : null;
    }

    /**
     * Sets the "exp" (expiration) claim in the JWT payload.
     *
     * @param string $dateTime The expiration time, which will be parsed and stored as a Unix timestamp.
     *
     * @see setTimestamp()
     *
     * @return self Returns the instance to allow method chaining.
     *
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     * @throws InvalidDateTimeException If the datetime string is in an invalid format.
     */
    public function setExpiration(string $dateTime): self
    {
        return $this->setClaimTimestamp('exp', $dateTime);
    }

    /**
     * Retrieves the expiration timestamp from the payload.
     *
     * This method fetches the value associated with the 'exp' (expiration) field
     * in the payload. The 'exp' field is expected to contain a string representing
     * a timestamp, or null if the field is not set.
     *
     * @see getField()
     *
     * @return int|null The expiration timestamp as int, or null if it is not present.
     */
    public function getExpiration(): int|null
    {
        $expires = $this->getClaim('exp');
        $resolvedExpires = is_int($expires) ? $expires : 0;

        return $resolvedExpires > 0 ? $resolvedExpires : null;
    }

    /**
     * Sets the "nbf" (not before) claim in the JWT payload.
     *
     * @param string $dateTime The not before time, which will be parsed and stored as a Unix timestamp.
     *
     * @see setTimestamp()
     *
     * @return self Returns the instance to allow method chaining.
     *
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     * @throws InvalidDateTimeException If the datetime string is in an invalid format.
     */
    public function setNotBefore(string $dateTime): self
    {
        return $this->setClaimTimestamp('nbf', $dateTime);
    }

    /**
     * Retrieves the not-before timestamp from the payload.
     *
     * This method fetches the value associated with the 'nbf' (not-before) field
     * in the payload. The 'nbf' field is expected to contain a string representing
     * a timestamp or null if the field is not set.
     *
     * @return int|null The not-before timestamp as int, or null if it is not present.
     */
    public function getNotBefore(): int|null
    {
        $nbf = $this->getClaim('nbf');
        $resolvedNbf = is_int($nbf) ? $nbf : 0;

        return $resolvedNbf > 0 ? $resolvedNbf : null;
    }

    /**
     * Checks whether a specific field exists in the token data (JWT payload).
     *
     * @param string|int $field The field to check.
     *
     * @return bool Returns true if the field exists, false otherwise.
     */
    public function hasClaim(string|int $field): bool
    {
        return isset($this->payload[$field]);
    }

    /**
     * Sets the encrypted payload.
     *
     * @param string $encryptedPayload The encrypted payload data.
     */
    public function setEncryptedPayload(string $encryptedPayload): self
    {
        $this->encryptedPayload = $encryptedPayload;
        return $this;
    }

    /**
     * Retrieves the encrypted payload.
     *
     * @return string The encrypted payload data, or null if not set.
     */
    public function getEncryptedPayload(): string
    {
        return $this->encryptedPayload;
    }

    /**
     * Parses and sets a timestamp field in the JWT payload.
     * Converts a datetime string into a Unix timestamp and stores it under the specified key.
     *
     * @param string $key      The key for the timestamp field (e.g., "iat", "nbf", "exp").
     * @param string $dateTime The datetime string to be converted into a timestamp.
     *
     * @see setClaim()
     *
     * @return self Returns the instance to allow method chaining.
     *
     * @throws InvalidDateTimeException If the datetime string is in an invalid format.
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     */
    private function setClaimTimestamp(string $key, string|int $dateTime): self
    {
        $adjustedDateTime = $this->buildValidDateTime($dateTime);

        return $this->setClaim($key, $adjustedDateTime->getTimestamp(), true);
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
                return (new DateTimeImmutable())->setTimestamp($timestamp);
            } catch (Exception $e) {
                throw new InvalidDateTimeException((string) $dateTime);
            }
        }

        // Ansonsten: relative Angabe oder absolute Datumsangabe
        try {
            $adjustedDateTime = @$this->getReferenceTime()->modify($dateTime);
        } catch (DateMalformedStringException) {
            throw new InvalidDateTimeException($dateTime);
        }

        // PHP < 8.3 Fallback-Schutz
        // @phpstan-ignore-next-line
        if (! $adjustedDateTime instanceof DateTimeImmutable) {
            throw new InvalidDateTimeException($dateTime);
        }

        return $adjustedDateTime;
    }

    /**
     * Checks whether the value is invalid (null, empty string, or empty array).
     *
     * @param string $key The key of the field.
     * @param mixed $value The value being checked.
     *
     * @return JwtPayload Returns the instance to allow method chaining.
     *
     * @throws EmptyFieldException if the value is empty.
     * @throws InvalidValueTypeException if the value is neither scalar nor array.
     */
    private function setClaim(string $key, mixed $value, bool $overwrite = false): self
    {
        $this->ensureValidClaim($key, $value);

        if ($this->hasClaim($key) === false || $overwrite) {
            $this->payload[$key] = $value;
        }

        return $this;
    }

    /**
     * Validates that a given JWT claim value is not empty or of invalid type.
     *
     * Rejects null values, empty strings, and empty arrays, as these are considered
     * semantically meaningless in the context of JWT claims. Also ensures that the
     * value is either a scalar or an array.
     *
     * @param mixed $key   The claim key being validated (used for error context).
     * @param mixed $value The claim value to validate.
     *
     * @throws EmptyFieldException       If the value is null, empty string, or empty array.
     * @throws InvalidValueTypeException If the value is neither scalar nor array.
     */
    private function ensureValidClaim(mixed $key, mixed $value): void
    {
        $key = $this->assertJsonKey($key);

        if ($this->isEmpty($value)) {
            throw new EmptyFieldException((string) $key);
        }

        if (! $this->isJsonValue($value)) {
            throw new InvalidValueTypeException((string) $key, gettype($value));
        }
    }

    private function isJsonValue(mixed $data): bool
    {
        return is_bool($data)
            || is_float($data)
            || is_int($data)
            || is_string($data)
            || is_null($data)
            || (is_array($data)
                && array_reduce($data, fn ($carry, $v) => $carry && $this->isJsonValue($v), true));
    }

    private function assertJsonKey(mixed $key): string|int
    {
        if (! is_string($key) && ! is_int($key)) {
            throw new InvalidKeyTypeException(gettype($key));
        }

        return $key;
    }

    private function isEmpty(mixed $value): bool
    {
        return $value === null || $value === '' || $value === [];
    }
}
