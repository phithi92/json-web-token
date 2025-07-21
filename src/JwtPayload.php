<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken;

use DateMalformedStringException;
use DateTimeImmutable;
use Phithi92\JsonWebToken\Exceptions\Json\JsonException;
use Phithi92\JsonWebToken\Exceptions\Payload\EmptyFieldException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidDateTimeException;
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
    private string $encryptedPayload;

    /**
     * @var array<string, int|string|array<string, int|string|array<string, int|string|null>|null>|null>
     */
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
    public static function fromJson(string $json): self
    {
        // Decode the JSON string into an associative array
        try {
            /**
             * @var array<string, string|int|float|bool|array<string, mixed>|null> $payload
             */
            $payload = JsonEncoder::decode($json, true);
        } catch (JsonException $e) {
            throw new InvalidFormatException('Header decoding failed: ' . $e->getMessage());
        }

        return self::fromArray($payload);
    }

    /**
     * Creates a new instance of JwtPayload from an associative array.
     *
     * This method takes an array of key-value pairs representing JWT payload data
     * and populates a JwtPayload instance with these values. Each key-value pair
     * from the input array is iteratively set within the instance, allowing fields
     * to be overwritten by default to ensure the payload reflects the provided data.
     *
     * @param array<string, string|int|float|bool|array<string, mixed>|null> $payload
     *
     * @return self A populated JwtPayload instance with the provided payload data.
     */
    public static function fromArray(array $payload): self
    {
        // Create a new instance of JwtPayload
        $instance = new self();

        // Iterate over the decoded data and set each key-value pair in the payload
        foreach ($payload as $key => $value) {
            if (! is_string($value) && ! is_int($value)) {
                continue;
            }

            $instance->setClaim($key, $value, true);
            // true allows overwriting fields
        }

        // Return the populated JwtPayload instance
        return $instance;
    }

    /**
     * Converts the token data (JWT payload) into an array.
     * Before returning the array, it validates the data.
     *
     * @see validate() Called to ensure the payload meets required criteria.
     * @see setField()
     * @see getField()
     *
     * @return array<string, string|int|float|bool|array<string, mixed>|null>
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

        return (array) $this->payload;
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
        return JsonEncoder::encode($this->toArray(), (JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }

    /**
     * array<int|string,
     * int|string|null>
     * Adds a field to the token data (JWT payload).
     * Ensures that the key is unique and the value is a valid type (scalar or array).
     *
     * @param string                                                              $key   The key of the field to add.
     * @param array<string, array<string,string>|int|string|null>|int|string|null $value
     *
     * @return self Returns the instance to allow method chaining.
     *
     * @throws InvalidValueTypeException if the value type is invalid.
     * @throws EmptyFieldException if the value is empty.
     */
    public function addClaim(string $key, string|int|array|null $value): self
    {
        return $this->setClaim($key, $value, false);
    }

    /**
     * Retrieves a specific field from the token data (JWT payload).
     *
     * @param string $claim The field to retrieve.
     *
     * @return string|int|array<string, string|int|float|bool|array<string, string|int|float|bool|null>|null>|null
     */
    public function getClaim(string $claim): string|int|array|null
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
     * @return array<string,mixed>|string|null The audience identifier as a string, or null if it is not present.
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
        $audience = (int) $this->getClaim('iat');
        return $audience > 0 ? $audience : null;
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
        $expires = (int) $this->getClaim('exp');
        return $expires > 0 ? $expires : null;
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
        $notBefore = (int) $this->getClaim('nbf');
        return $notBefore > 0 ? $notBefore : null;
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
    private function setClaimTimestamp(string $key, string $dateTime): self
    {
        try {
            // Suppress warnings temporarily and handle them manually.
            $adjustedDateTime = @$this->dateTimeImmutable->modify($dateTime);
        } catch (DateMalformedStringException) {
            throw new InvalidDateTimeException($dateTime);
        }

        // Handle invalid DateTime values explicitly for PHP versions below 8.3.
        // @phpstan-ignore-next-line
        if (PHP_VERSION_ID < 80300 && ! $adjustedDateTime instanceof DateTimeImmutable) {
            throw new InvalidDateTimeException($dateTime);
        }

        return $this->setClaim($key, $adjustedDateTime->getTimestamp(), true);
    }

    /**
     * Checks whether the value is invalid (null, empty string, or empty array).
     *
     * @param string                                               $key   The key of the field.
     * @param array<string, array<string, string>|int|string|null> $value The value being checked.
     *
     * @return JwtPayload Returns the instance to allow method chaining.
     *
     * @throws EmptyFieldException if the value is empty.
     * @throws InvalidValueTypeException if the value is neither scalar nor array.
     */
    private function setClaim(string $key, string|int|array|null $value, bool $overwrite = false): self
    {
        $this->ensureValidClaimValue($key, $value);

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
     * @param string $key   The claim key being validated (used for error context).
     * @param mixed  $value The claim value to validate.
     *
     * @throws EmptyFieldException        If the value is null, empty string, or empty array.
     * @throws InvalidValueTypeException If the value is neither scalar nor array.
     */
    private function ensureValidClaimValue(string $key, mixed $value): void
    {
        // Check if the value is null
        $isNull = $value === null;

        // Check if the value is an empty string
        $isEmptyString = is_string($value) && trim($value) === '';

        // Check if the value is an empty array
        $isEmptyArray = is_array($value) && empty($value);

        if ($isNull || $isEmptyString || $isEmptyArray) {
            throw new EmptyFieldException($key);
        }

        if (is_scalar($value) === false && is_array($value) === false) {
            throw new InvalidValueTypeException();
        }
    }
}
