<?php

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Exception;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;
use DateTimeImmutable;
use DateMalformedStringException;
use ErrorException;

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
    // Array to store token data (JWT payload)
    private array $payload = [];

    // DateTimeImmutable object to handle date-related operations
    private DateTimeImmutable $dateTimeImmutable;

    /**
     * Constructor initializes the DateTimeImmutable object.
     * The DateTimeImmutable instance will be used for managing date-related claims (e.g., "iat", "nbf", "exp").
     */
    public function __construct()
    {
        $this->dateTimeImmutable = new DateTimeImmutable();
    }

    /**
     * Adds a field to the token data (JWT payload).
     * Ensures that the key is unique and the value is a valid type (scalar or array).
     *
     * @param  string $key   The key of the field to add.
     * @param  mixed  $value The value to associate with the key (must be scalar or array).
     * @return self Returns the instance to allow method chaining.
     * @throws InvalidArgument If the key is not unique or the value type is invalid.
     */
    public function addField(string $key, mixed $value): self
    {
        $this->setField($key, $value, false);
        return $this;
    }

    /**
     * Sets the "iss" (issuer) claim in the JWT payload.
     *
     * @param  string $issuer The issuer of the JWT.
     * @return self Returns the instance to allow method chaining.
     */
    public function setIssuer(string $issuer): self
    {
        $this->addField('iss', $issuer);
        return $this;
    }

    /**
     * Sets the "aud" (audience) claim in the JWT payload.
     *
     * @param  string|array $audience The intended audience of the JWT. Can be a string or an array of strings.
     * @return self Returns the instance to allow method chaining.
     */
    public function setAudience(string|array $audience): self
    {
        $this->addField('aud', $audience);
        return $this;
    }

    /**
     * Sets the "iat" (issued at) claim in the JWT payload.
     *
     * @param  string $dateTime The issued at time, which will be parsed and stored as a Unix timestamp.
     * @return self Returns the instance to allow method chaining.
     */
    public function setIssuedAt(string $dateTime): self
    {
        $this->setTimestamp('iat', $dateTime);
        return $this;
    }

    /**
     * Sets the "exp" (expiration) claim in the JWT payload.
     *
     * @param  string $dateTime The expiration time, which will be parsed and stored as a Unix timestamp.
     * @return self Returns the instance to allow method chaining.
     */
    public function setExpiration(string $dateTime): self
    {
        $this->setTimestamp('exp', $dateTime);
        return $this;
    }

    /**
     * Sets the "nbf" (not before) claim in the JWT payload.
     *
     * @param  string $dateTime The not before time, which will be parsed and stored as a Unix timestamp.
     * @return self Returns the instance to allow method chaining.
     */
    public function setNotBefore(string $dateTime): self
    {
        $this->setTimestamp('nbf', $dateTime);
        return $this;
    }

    /**
     * Retrieves a specific field from the token data (JWT payload).
     *
     * @param  string $field The field to retrieve.
     * @return mixed|null Returns the field value, or null if it does not exist and $throwIfMissing is false.
     */
    public function getField(string $field): mixed
    {
        if (!array_key_exists($field, $this->payload)) {
            return null;
        }
        return $this->payload[$field];
    }

    /**
     * Validates that the required fields are present and checks the temporal claims.
     * This method does NOT validate the 'iss' and 'aud' claims, allowing more flexible use.
     *
     * @throws PayloadError If required fields are missing or temporal claims are invalid.
     */
    public function validate(): void
    {
        $requiredFields = ['exp']; // Only check basic required claims (exclude 'iss' and 'aud' for now)
        foreach ($requiredFields as $field) {
            if (!$this->hasField($field)) {
                throw new Exception\Payload\MissingData($field);
            }
        }

        // Validate temporal claims (iat, nbf, exp)
        $this->validateTemporalClaims();
    }

    /**
     * Optionally validates that the 'iss' (issuer) claim matches the expected issuer.
     *
     * @param  string $expectedIssuer The expected issuer of the JWT.
     * @throws InvalidArgument If the issuer does not match the expected value.
     */
    public function validateIssuer(string $expectedIssuer): void
    {
        $issuer = $this->getField('iss');
        if ($issuer === null) {
            throw new Exception\Payload\MissingData('iss');
        }
        if ($issuer !== $expectedIssuer) {
            throw new Exception\Payload\InvalidIssuer($expectedIssuer, $issuer);
        }
    }

    /**
     * Optionally validates that the 'aud' (audience) claim matches the expected audience.
     *
     * @param  string|array $expectedAudience The expected audience(s) of the JWT.
     * @throws InvalidArgument If the audience does not match the expected value.
     */
    public function validateAudience(string|array $expectedAudience): void
    {
        $audience = $this->getField('aud');

        if ($audience === null) {
            throw new Exception\Payload\MissingData('aud');
        }

        // Ensure both variables are arrays for consistent processing
        $audience = (array) $audience;
        $expectedAudience = (array) $expectedAudience;

        // Check if there's any overlap between expected and actual audience
        if (empty(array_intersect($expectedAudience, $audience))) {
            throw new Exception\Payload\AudienceInvalid();
        }
    }


    /**
     * Creates a new instance of JwtPayload from a JSON string.
     * This static method parses the JSON input and populates the payload fields accordingly.
     *
     * @param  string $json A JSON-encoded string representing the JWT payload data.
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
    public static function fromArray(array $payload): self
    {
        // Create a new instance of JwtPayload
        $instance = new self();

        // Iterate over the decoded data and set each key-value pair in the payload
        foreach ($payload as $key => $value) {
            $instance->setField($key, $value, true);  // true allows overwriting fields
        }

        // Return the populated JwtPayload instance
        return $instance;
    }

    /**
     * Converts the token data (JWT payload) into an array.
     * Before returning the array, it validates the data.
     *
     * @return array The complete JWT payload as an associative array.
     * @throws PayloadError If validation fails.
     */
    public function toArray(): array
    {
        if ($this->getField('exp') === null) {
            $this->setField('iat', now());
        }

        $this->validate();
        return $this->payload;
    }

    /**
     * Serializes the JWT payload data to a JSON-encoded string.
     *
     * Converts the payload properties to an array using `toArray`, then encodes them
     * as a JSON string suitable for inclusion in a JWT.
     *
     * @return string The JSON-encoded representation of the JWT payload.
     */
    public function toJson(): string
    {
        return JsonEncoder::encode($this->toArray());
    }

    /**
     * Validates the consistency of the temporal claims ("iat", "nbf", "exp").
     * Ensures that "iat" is earlier than "exp", and that "nbf" falls within the valid time range.
     *
     * @throws PayloadError If the temporal claims are inconsistent.
     */
    private function validateTemporalClaims(): void
    {
        $iat = $this->getField('iat');  // Issued At
        $nbf = $this->getField('nbf');  // Not Before
        $exp = $this->getField('exp');  // Expiration
        $now = time(); // Current Unix timestamp

        // Check if "iat" is earlier than "exp"
        if ($iat && $exp && $iat > $exp) {
            throw new Exception\Payload\Expired();
        }

        // Check if "nbf" is earlier than "exp"
        if ($nbf && $exp && $nbf > $exp) {
            throw new Exception\Payload\NotBeforeOlderThanExp();
        }

        // Check if "nbf" is later than or equal to "iat"
        if ($iat && $nbf && $nbf < $iat) {
            throw new Exception\Payload\NotBeforeOlderThanIat();
        }

        // Validate if the token is valid based on the current time
        if ($exp && $now >= $exp) {
            throw new Exception\Payload\Expired();
        }

        if ($nbf && $now < $nbf) {
            throw new Exception\Payload\NotYetValid();
        }
    }
    /**
     * Checks whether a specific field exists in the token data (JWT payload).
     *
     * @param  string $field The field to check.
     * @return bool Returns true if the field exists, false otherwise.
     */
    private function hasField(string $field): bool
    {
        return array_key_exists($field, $this->payload);
    }

    /**
     * Parses and sets a timestamp field in the JWT payload.
     * Converts a datetime string into a Unix timestamp and stores it under the specified key.
     *
     * @param  string $key      The key for the timestamp field (e.g., "iat", "nbf", "exp").
     * @param  string $dateTime The datetime string to be converted into a timestamp.
     * @throws InvalidArgument If the datetime string is in an invalid format.
     */
    private function setTimestamp(string $key, string $dateTime): void
    {
        try {
            $dateTimeImmutable = $this->dateTimeImmutable->modify($dateTime);

            if (!$dateTimeImmutable) {
                throw new Exception\Payload\InvalidDateTime($dateTime);
            }
        } catch (DateMalformedStringException $e) {
            throw new Exception\Payload\InvalidDateTime($dateTime);
        } catch (ErrorException $e) {
            throw new Exception\Payload\InvalidDateTime($dateTime);
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
     * @return void
     * @throws InvalidArgument If the value type is invalid.
     */
    private function setField(string $key, mixed $value, bool $overwrite = false): void
    {
        if (empty($value)) {
            throw new Exception\Payload\EmptyValueException($key);
        }

        if (!is_scalar($value) && !is_array($value)) {
            throw new Exception\Payload\InvalidValue();
        }

        // Nur überschreiben, wenn $overwrite true ist oder das Feld noch nicht existiert
        if (!$this->hasField($key) || $overwrite) {
            $this->payload[$key] = $value;
        }
    }
}
