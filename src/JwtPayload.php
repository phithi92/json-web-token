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
 * Key Features:
 * - **Field Management**: Provides methods to add, retrieve, and set fields within the payload.
 * - **Temporal Claim Validation**: Ensures that temporal claims like "issued at" (iat),
 *   "not before" (nbf), and "expiration" (exp) are valid and consistent.
 * - **Flexible Audience and Issuer Validation**: Supports optional validation of the "aud" (audience)
 *   and "iss" (issuer) claims to ensure the token is intended for the correct recipient and issuer.
 * - **Serialization**: Includes methods to convert the payload into an array or JSON format.
 *
 * @package json-web-token
 * @author Phillip Thiele <development@phillip-thiele.de>
 * @version 1.0.0
 * @since 1.0.0
 * @license https://github.com/phithi92/json-web-token/blob/main/LICENSE MIT License
 * @link https://github.com/phithi92/json-web-token Project on GitHub
 */
class JwtPayload
{
    // stdClass to store token data (JWT payload)
    private stdClass $payload;

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
     * Validates the JWT (JSON Web Token) payload fields to ensure they adhere to the
     * required conditions based on issuance, expiration, and not-before timestamps.
     *
     * Steps:
     * - Retrieves the 'iat' (issued at), 'nbf' (not before), and 'exp' (expiration) fields.
     * - Ensures mandatory fields 'iat' and 'exp' are present.
     * - Validates that 'iat' is not later than 'exp', indicating the token was issued before its expiration.
     * - Checks 'nbf' to confirm it is not later than 'exp', ensuring the token's validity window is logical.
     * - Confirms that 'nbf' is not set earlier than 'iat', maintaining temporal consistency.
     * - Validates the token’s expiration and activation times based on the current time:
     *
     * @see getField() Used to retrieve the 'aud' claim from the payload.
     * @throws ValueNotFoundException if 'iat' or 'exp' is missing.
     * @throws IatEarlierThanExpException if 'iat' is after 'exp'.
     * @throws NotBeforeOlderThanExpException if 'nbf' is after 'exp'.
     * @throws NotBeforeOlderThanIatException if 'nbf' is before 'iat'.
     * @throws ExpiredPayloadException if the token has expired.
     * @throws NotYetValidException if the token is not yet valid.
     */
    public function validate(): void
    {
        $iat = $this->getField('iat');  // Issued At
        $nbf = $this->getField('nbf');  // Not Before
        $exp = $this->getField('exp');  // Expiration
        $now = $this->dateTimeImmutable->getTimestamp(); // Current Unix timestamp

        // Check if "iat" exist"
        if ($iat === null) {
            throw new ValueNotFoundException('iat');
        }

        // Check if "exp" exist"
        if ($exp === null) {
            throw new ValueNotFoundException('exp');
        }

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
     * Optionally validates that the 'iss' (issuer) claim matches the expected issuer.
     *
     * @param  string $expectedIssuer The expected issuer of the JWT.
     * @see getField() Used to retrieve the 'aud' claim from the payload.
     * @throws InvalidIssuerException If the issuer does not match the expected value.
     */
    public function validateIssuer(string $expectedIssuer): void
    {
        $issuer = $this->getField('iss');
        if ($issuer === null || $issuer !== $expectedIssuer) {
            throw new InvalidIssuerException($expectedIssuer, $issuer);
        }
    }

    /**
     * Optionally validates that the 'aud' (audience) claim matches the expected audience.
     *
     * @param  string|array $expectedAudience The expected audience(s) of the JWT.
     * @see getField() Used to retrieve the 'aud' claim from the payload.
     * @see validateIssuer() For validating the 'iss' (issuer) claim.
     * @see validateAudience() For validating the 'aud' (audience) claim.
     * @throws InvalidAudienceException If the audience does not match the expected value.
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
     * @uses JsonEncoder Encodes the array representation of the object into JSON.
     * @see fromArray()
     * @return self Returns an instance of JwtPayload with fields populated from the JSON data.
     * @throws InvalidArgumentException If the JSON cannot be decoded or the data is invalid.
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
     * @param  array $payload An associative array containing the JWT payload data,
     *                        where keys are claim names (e.g., 'iss', 'aud') and
     *                        values are the corresponding claim values.
     * @return self A populated JwtPayload instance with the provided payload data.
     */
    public static function fromArray(array|stdClass $payload): self
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
     * @see validate() Called to ensure the payload meets required criteria.
     * @see setField()
     * @see getField()
     * @return array The complete JWT payload as an associative array.
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     */
    public function toArray(): array
    {
        if ($this->getField('iat') === null) {
            $iat = $this->getField('exp') ?? $this->dateTimeImmutable->getTimestamp();
            $this->setField('iat', $iat);
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
     * @uses JsonEncoder Encodes the array representation of the object into JSON.
     * @see toArray()
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
     * @see setField()
     * @return self Returns the instance to allow method chaining.
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     */
    public function addField(string $key, mixed $value): self
    {
        $this->setField($key, $value, false);
        return $this;
    }

    /**
     * Retrieves a specific field from the token data (JWT payload).
     *
     * @param  string $field The field to retrieve.
     * @return string|array|null The value of the specified field, or null if it does not exist.
     */
    public function getField(string $field): string|array|null
    {
        return $this->payload->{$field} ?? null;
    }

    /**
     * Sets the "iss" (issuer) claim in the JWT payload.
     *
     * @param  string $issuer The issuer of the JWT.
     * @see addField()
     * @return self Returns the instance to allow method chaining.
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     */
    public function setIssuer(string $issuer): self
    {
        $this->addField('iss', $issuer);
        return $this;
    }

    /**
     * Retrieves the issuer identifier from the payload.
     *
     * This method fetches the value associated with the 'iss' (issuer) field
     * in the payload. The 'iss' field is expected to contain a string identifying
     * the issuer, or null if the field is not set.
     *
     * @see getField()
     * @return string|null The issuer identifier as a string, or null if it is not present.
     */
    public function getIssuer(): ?string
    {
        return $this->getField('iss');
    }

    /**
     * Sets the "aud" (audience) claim in the JWT payload.
     *
     * @param  string|array $audience The intended audience of the JWT. Can be a string or an array of strings.
     * @see addField()
     * @return self Returns the instance to allow method chaining.
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     */
    public function setAudience(string|array $audience): self
    {
        $this->addField('aud', $audience);
        return $this;
    }

    /**
     * Retrieves the audience information from the payload.
     *
     * This method fetches the value associated with the 'aud' (audience) field
     * in the payload. The 'aud' field is expected to contain a string identifying
     * the intended audience, or null if the field is not set.
     *
     * @see getField()
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
     * @see setTimestamp()
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     */
    public function setIssuedAt(string $dateTime): self
    {
        $this->setTimestamp('iat', $dateTime);
        return $this;
    }

    /**
     * Retrieves the issued-at timestamp from the payload.
     *
     * This method fetches the value associated with the 'iat' (issued-at) field
     * in the payload. The 'iat' field is expected to contain a string representing
     * a timestamp, or null if the field is not set.
     *
     * @see getField()
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
     * @see setTimestamp()
     * @return self Returns the instance to allow method chaining.
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     * @throws InvalidDateTimeException If the datetime string is in an invalid format.
     */
    public function setExpiration(string $dateTime): self
    {
        $this->setTimestamp('exp', $dateTime);
        return $this;
    }

    /**
     * Retrieves the expiration timestamp from the payload.
     *
     * This method fetches the value associated with the 'exp' (expiration) field
     * in the payload. The 'exp' field is expected to contain a string representing
     * a timestamp, or null if the field is not set.
     *
     * @see getField()
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
     * @see setTimestamp()
     * @return self Returns the instance to allow method chaining.
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     * @throws InvalidDateTimeException If the datetime string is in an invalid format.
     */
    public function setNotBefore(string $dateTime): self
    {
        $this->setTimestamp('nbf', $dateTime);
        return $this;
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
     * @see setField()
     * @throws InvalidDateTimeException If the datetime string is in an invalid format.
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     */
    private function setTimestamp(string $key, string $dateTime): void
    {
        try {
            $dateTimeImmutable = $this->dateTimeImmutable->modify($dateTime);

            if ($dateTimeImmutable === false) {
                throw new InvalidDateTimeException($dateTime);
            }
        } catch (Exception) {
            throw new InvalidDateTimeException($dateTime);
        }

        $this->setField($key, $dateTimeImmutable->getTimestamp(), true);
    }

    /**
     * Adds or updates a field in the token data (JWT payload).
     * If the key already exists, it will only be updated if $overwrite is set to true.
     *
     * @param  string $key       The key of the field to add or update.
     * @param  mixed  $value     The value to associate with the key (must be scalar or array).
     * @param  bool   $overwrite Determines whether to overwrite an existing field.
     * @see hasField() Used to check if a key already exists in the payload.
     * @return void
     * @throws InvalidValueTypeException If the value type is invalid.
     * @throws EmptyFieldException If the value is empty.
     */
    private function setField(string $key, mixed $value, bool $overwrite = false): void
    {
        if (empty($value)) {
            throw new EmptyFieldException($key);
        }

        if (!is_scalar($value) && !is_array($value)) {
            throw new InvalidValueTypeException();
        }

        if (!$this->hasField($key) || $overwrite) {
            $this->payload->{$key} = $value;
        }
    }
}
