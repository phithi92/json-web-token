<?php

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Exceptions\Payload\EmptyFieldException;
use Phithi92\JsonWebToken\Exceptions\Payload\ExpiredPayloadException;
use Phithi92\JsonWebToken\Exceptions\Payload\IatEarlierThanExpException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidAudienceException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidDateTimeException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidIssuerException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidValueTypeException;
use Phithi92\JsonWebToken\Exceptions\Payload\NotBeforeOlderThanExpException;
use Phithi92\JsonWebToken\Exceptions\Payload\NotBeforeOlderThanIatException;
use Phithi92\JsonWebToken\Exceptions\Payload\NotYetValidException;
use Phithi92\JsonWebToken\Exceptions\Payload\ValueNotFoundException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidJti;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;
use DateTimeImmutable;
use Exception;
use stdClass;

/**
 * JwtPayload represents the payload segment of a JSON Web Token (JWT).
 *
 * This class manages the creation, validation, and manipulation of JWT payload data.
 * It supports setting standard JWT claims (e.g., "iss", "aud", "iat", "exp", "nbf")
 * and allows custom claims to be added as well. Temporal claims, such as "iat", "nbf",
 * and "exp," are managed with DateTimeImmutable to ensure consistency in date-related
 * operations.
 *
 * @package Phithi92\JsonWebToken
 * @author  Phillip Thiele <development@phillip-thiele.de>
 * @version 1.0.0
 * @since   1.0.0
 * @license https://github.com/phithi92/json-web-token/blob/main/LICENSE MIT License
 * @link    https://github.com/phithi92/json-web-token Project on GitHub
 */
final class JwtPayload
{
    // stdClass to store token data (JWT payload)
    private object $payload;

    // DateTimeImmutable object to handle date-related operations
    private readonly DateTimeImmutable $dateTimeImmutable;

    /**
     * Constructor initializes the DateTimeImmutable object.
     * The DateTimeImmutable instance will be used for managing date-related claims (e.g., "iat", "nbf", "exp").
     */
    public function __construct()
    {
        $this->payload = new stdClass();
        $this->dateTimeImmutable = new DateTimeImmutable();
    }

    /**
     * Validates JWT payload fields ('iat', 'nbf', 'exp', 'usage') to ensure correct issuance,
     * expiration, validity, and usage constraints.
     *
     * This method performs the following checks:
     * - 'iat' and 'exp' are present, with 'iat' occurring before or at the same time as 'exp'.
     * - 'nbf' is within valid bounds relative to 'iat' and 'exp'.
     * - The token's activation ('nbf') and expiration ('exp') times are valid relative to the current time.
     * - The 'usage' field, which determines if the token is intended for one-time or reusable access, is
     *   either 'reusable' or 'one_time' if present.
     *
     * @throws ValueNotFoundException if 'iat' or 'exp' is missing.
     * @throws IatEarlierThanExpException if 'iat' is later than 'exp'.
     * @throws NotBeforeOlderThanExpException if 'nbf' is after 'exp'.
     * @throws NotBeforeOlderThanIatException if 'nbf' is before 'iat'.
     * @throws ExpiredPayloadException if the token has expired.
     * @throws NotYetValidException if the token is not yet valid.
     */
    public function validate(): void
    {
        // Check if "iat" exists
        if ($this->getField('iat') === null) {
            throw new ValueNotFoundException('iat');
        }

        // Check if "exp" exists
        if ($this->getField('exp') === null) {
            throw new ValueNotFoundException('exp');
        }

        $iat = (int) $this->getField('iat');  // Issued At
        $nbf = (int) $this->getField('nbf');  // Not Before
        $exp = (int) $this->getField('exp');  // Expiration
        $now = $this->dateTimeImmutable->getTimestamp(); // Current Unix timestamp


        // Check if "iat" is earlier than "exp"
        if ($iat && $exp && $iat > $exp) {
            throw new IatEarlierThanExpException();
        }

        // Check if "nbf" is earlier than "exp"
        if ($nbf && $exp && $nbf > $exp) {
            throw new NotBeforeOlderThanExpException();
        }

        // Check if "nbf" is later than or equal to "iat"
        if ($iat && $nbf && $nbf < $iat) {
            throw new NotBeforeOlderThanIatException();
        }

        // Validate if the token is valid based on the current time
        if ($exp && $now >= $exp) {
            throw new ExpiredPayloadException();
        }

        if ($nbf && $now < $nbf) {
            throw new NotYetValidException();
        }
    }

    /**
     * Optionally validates whether the 'iss' (issuer) claim matches the expected issuer.
     *
     * @param  string $expectedIssuer The expected issuer of the JWT.
     * @see    getField() Used to retrieve the 'iss' claim from the payload.
     * @throws InvalidIssuerException if the issuer does not match the expected value.
     */
    public function validateIssuer(string $expectedIssuer): void
    {
        $issuer = $this->getField('iss');
        if (!is_string($issuer) || $issuer !== $expectedIssuer) {
            throw new InvalidIssuerException($expectedIssuer, (string) $issuer);
        }
    }

    /**
     * Optionally validates whether the 'aud' (audience) claim matches the expected audience.
     *
     * @param  string|array<string> $expectedAudience The expected audience(s) of the JWT.
     * @see    getField() Used to retrieve the 'aud' claim from the payload.
     * @throws InvalidAudienceException if the audience does not match the expected value.
     */
    public function validateAudience(string|array $expectedAudience): void
    {
        $audience = $this->getField('aud');

        if ($audience === null) {
            throw new InvalidAudienceException();
        }

        // Ensure $audience is an array for consistent processing
        $actualAudience = is_array($audience) ? array_flip($audience) : [$audience];

        // Convert $expectedAudience to an array if it’s a string
        $expectedAudiences = is_array($expectedAudience) ? $expectedAudience : [$expectedAudience];

        // Use a loop to check for any overlap between expected and actual audiences
        $isValid = false;
        foreach ($expectedAudiences as $expected) {
            if (isset($actualAudience[$expected])) {
                $isValid = true;
                break; // Exit the loop as soon as a match is found
            }
        }

        if ($isValid === false) {
            throw new InvalidAudienceException();
        }
    }

    /**
     * Creates a new instance of JwtPayload from a JSON string.
     * This static method parses the JSON input and populates the payload fields accordingly.
     *
     * @param  string $json A JSON-encoded string representing the JWT payload data.
     * @uses   JsonEncoder Encodes the array representation of the object into JSON.
     * @see    fromArray()
     * @return self Returns an instance of JwtPayload with fields populated from the JSON data.
     */
    public static function fromJson(string $json): self
    {
        // Decode the JSON string into an associative array
        $payload = JsonEncoder::decode($json);

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
     * @param  array<string,string> $payload An associative array containing the JWT payload data,
     *                        where keys are claim names (e.g., 'iss', 'aud') and
     *                        values are the corresponding claim values.
     * @return self A populated JwtPayload instance with the provided payload data.
     */
    public static function fromArray(array|object $payload): self
    {
        // Create a new instance of JwtPayload
        $instance = new self();

        // Iterate over the decoded data and set each key-value pair in the payload
        foreach ($payload as $key => $value) {
            $instance->setField($key, $value, true);  // true allows overwriting fields
        }

        $instance->validate();

        // Return the populated JwtPayload instance
        return $instance;
    }

    /**
     * Converts the token data (JWT payload) into an array.
     * Before returning the array, it validates the data.
     *
     * @see    validate() Called to ensure the payload meets required criteria.
     * @see    setField()
     * @see    getField()
     * @return array<string,string> The complete JWT payload as an associative array.
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     */
    public function toArray(): array
    {
        if ($this->getField('iat') === null) {
            $this->setTimestamp('iat', 'now');
        }

        $this->validate();

        return (array) $this->payload;
    }

    /**
     * Serializes the JWT payload data to a JSON-encoded string.
     *
     * Converts the payload properties to an array using `toArray`, then encodes them
     * as a JSON string suitable for inclusion in a JWT.
     *
     * @uses   JsonEncoder Encodes the array representation of the object into JSON.
     * @see    toArray()
     * @return string The JSON-encoded representation of the JWT payload.
     */
    public function toJson(): string
    {
        return JsonEncoder::encode($this->toArray());
    }

    /**
     * Adds a field to the token data (JWT payload).
     * Ensures that the key is unique and the value is a valid type (scalar or array).
     *
     * @param  string $key   The key of the field to add.
     * @param  mixed  $value The value to associate with the key (must be scalar or array).
     * @return self Returns the instance to allow method chaining.
     * @throws InvalidValueTypeException if the value type is invalid.
     * @throws EmptyFieldException if the value is empty.
     */
    public function addField(string $key, mixed $value): self
    {
        return $this->setField($key, $value, false);
    }

    /**
     * Retrieves a specific field from the token data (JWT payload).
     *
     * @param  string $field The field to retrieve.
     * @return string|array<mixed>|null The value of the specified field, or null if it does not exist.
     */
    public function getField(string $field): string|array|null
    {
        return $this->payload->{$field} ?? null;
    }

    /**
     * Sets the "iss" (issuer) claim in the JWT payload.
     *
     * @param  string $issuer The issuer of the JWT.
     * @see    addField()
     * @return self Returns the instance to allow method chaining.
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     */
    public function setIssuer(string $issuer): self
    {
        return $this->addField('iss', $issuer);
    }

    /**
     * Retrieves the issuer identifier from the payload.
     *
     * This method fetches the value associated with the 'iss' (issuer) field
     * in the payload. The 'iss' field is expected to contain a string identifying
     * the issuer, or null if the field is not set.
     *
     * @see    getField()
     * @return string|null The issuer identifier as a string, or null if it is not present.
     */
    public function getIssuer(): ?string
    {
        return $this->getField('iss');
    }

    /**
     * Sets the "aud" (audience) claim in the JWT payload.
     *
     * @param  string|array<string> $audience The intended audience of the JWT. Can be a string or an array of strings.
     * @see    addField()
     * @return self Returns the instance to allow method chaining.
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     */
    public function setAudience(string|array $audience): self
    {
        return $this->addField('aud', $audience);
    }

    /**
     * Retrieves the audience information from the payload.
     *
     * This method fetches the value associated with the 'aud' (audience) field
     * in the payload. The 'aud' field is expected to contain a string identifying
     * the intended audience, or null if the field is not set.
     *
     * @see    getField()
     * @return string|null The audience identifier as a string, or null if it is not present.
     */
    public function getAudience(): ?string
    {
        return $this->getField('aud');
    }

    /**
     * Sets the "iat" (issued at) claim in the JWT payload.
     *
     * @param  string $dateTime The issued at time, which will be parsed and stored as a Unix timestamp.
     * @return self Returns the instance to allow method chaining.
     * @see    setTimestamp()
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     */
    public function setIssuedAt(string $dateTime): self
    {
        return $this->setTimestamp('iat', $dateTime);
    }

    /**
     * Retrieves the issued-at timestamp from the payload.
     *
     * This method fetches the value associated with the 'iat' (issued-at) field
     * in the payload. The 'iat' field is expected to contain a string representing
     * a timestamp, or null if the field is not set.
     *
     * @see    getField()
     * @return string|null The issued-at timestamp as a string, or null if it is not present.
     */
    public function getIssuedAt(): ?string
    {
        return $this->getField('iat');
    }

    /**
     * Sets the "exp" (expiration) claim in the JWT payload.
     *
     * @param  string $dateTime The expiration time, which will be parsed and stored as a Unix timestamp.
     * @see    setTimestamp()
     * @return self Returns the instance to allow method chaining.
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     * @throws InvalidDateTimeException If the datetime string is in an invalid format.
     */
    public function setExpiration(string $dateTime): self
    {
        return $this->setTimestamp('exp', $dateTime);
    }

    /**
     * Retrieves the expiration timestamp from the payload.
     *
     * This method fetches the value associated with the 'exp' (expiration) field
     * in the payload. The 'exp' field is expected to contain a string representing
     * a timestamp, or null if the field is not set.
     *
     * @see    getField()
     * @return string|null The expiration timestamp as a string, or null if it is not present.
     */
    public function getExpiration(): ?string
    {
        return $this->getField('exp');
    }

    /**
     * Sets the "nbf" (not before) claim in the JWT payload.
     *
     * @param  string $dateTime The not before time, which will be parsed and stored as a Unix timestamp.
     * @see    setTimestamp()
     * @return self Returns the instance to allow method chaining.
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     * @throws InvalidDateTimeException If the datetime string is in an invalid format.
     */
    public function setNotBefore(string $dateTime): self
    {
        return $this->setTimestamp('nbf', $dateTime);
    }

    /**
     * Retrieves the not-before timestamp from the payload.
     *
     * This method fetches the value associated with the 'nbf' (not-before) field
     * in the payload. The 'nbf' field is expected to contain a string representing
     * a timestamp or null if the field is not set.
     *
     * @return string|null The not-before timestamp as a string, or null if it is not present.
     */
    public function getNotBefore(): ?string
    {
        return $this->getField('nbf');
    }

    /**
     * Checks whether a specific field exists in the token data (JWT payload).
     *
     * @param  string $field The field to check.
     * @return bool Returns true if the field exists, false otherwise.
     */
    private function hasField(string $field): bool
    {
        return isset($this->payload->{$field});
    }

    /**
     * Parses and sets a timestamp field in the JWT payload.
     * Converts a datetime string into a Unix timestamp and stores it under the specified key.
     *
     * @param  string $key      The key for the timestamp field (e.g., "iat", "nbf", "exp").
     * @param  string $dateTime The datetime string to be converted into a timestamp.
     * @see    setField()
     * @return self Returns the instance to allow method chaining.
     * @throws InvalidDateTimeException If the datetime string is in an invalid format.
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     */
    private function setTimestamp(string $key, string $dateTime): self
    {
        try {
            $adjustedDateTime = $this->dateTimeImmutable->modify($dateTime);
        } catch (Exception) {
            throw new InvalidDateTimeException($dateTime);
        }

        // For PHP versions below 8.3, it is important to explicitly handle
        // invalid DateTime values since errors are not automatically thrown.
        // @phpstan-ignore-next-line (necessary if phpstan reports a warning)
        if (PHP_VERSION_ID < 80300 && !$adjustedDateTime) {
            throw new InvalidDateTimeException($dateTime);
        }

        return $this->setField($key, $adjustedDateTime->getTimestamp(), true);
    }

    /**
     * Checks whether the value is invalid (null, empty string, or empty array).
     *
     * @param  string $key   The key of the field.
     * @param  mixed  $value The value being checked.
     * @return self Returns the instance to allow method chaining.
     * @throws EmptyFieldException if the value is empty.
     * @throws InvalidValueTypeException if the value is neither scalar nor array.
     */
    private function setField(string $key, mixed $value, bool $overwrite = false): self
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

        if (false === is_scalar($value) &&  false === is_array($value)) {
            throw new InvalidValueTypeException();
        }

        if (false === $this->hasField($key) || $overwrite) {
            $this->payload->{$key} = $value;
        }

        return $this;
    }
}
