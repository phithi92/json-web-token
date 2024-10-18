<?php

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Exception\InvalidArgumentException;
use Phithi92\JsonWebToken\Exception\InvalidTokenException;
use DateTimeImmutable;

/**
 * Class PayloadBuilder
 *
 * Provides a builder pattern for constructing the payload of a JWT (JSON Web Token).
 * The class allows setting standard JWT claims (issuer, audience, issued at, expiration, etc.)
 * and ensures validity of the temporal claims (e.g., "iat", "nbf", and "exp").
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class PayloadBuilder
{
    // Error messages for various invalid operations
    const ERROR_NOT_UNIQUE = 'Key is not unique.'; // Error when trying to add a duplicate key
    const ERROR_MISSING_FIELD = '%s field is missing.'; // Error when a required field is missing
    const ERROR_DATE_FORMAT = "Invalid date format."; // Error for invalid date format
    const ERROR_INVALID_FIELD_TYPE = "Invalid field value type."; // Error when field value type is not allowed
    const INVALID_TOKEN_IAT_TO_EARLY = "Issued at (iat) must be earlier than expiration (exp).";
    const INVALID_TOKEN_NBF_TO_EARLY = "Not before (nbf) must be earlier than expiration (exp).";
    const INVALID_TOKEN_NBF_EARLY_IAT = "Not before (nbf) must be later than or equal to issued at (iat).";

    // Array to store token data (JWT payload)
    private array $token_data = [];

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
     * Sets the "iss" (issuer) claim in the JWT payload.
     *
     * @param string $issuer The issuer of the JWT.
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
     * @param string|array $audience The intended audience of the JWT. Can be a string or an array of strings.
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
     * @param string $dateTime The issued at time, which will be parsed and stored as a Unix timestamp.
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
     * @param string $dateTime The expiration time, which will be parsed and stored as a Unix timestamp.
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
     * @param string $dateTime The not before time, which will be parsed and stored as a Unix timestamp.
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
     * @param string $field The field to retrieve.
     * @param bool $throwIfMissing If true, an exception will be thrown if the field is not present.
     * @return mixed|null Returns the field value, or null if it does not exist and $throwIfMissing is false.
     * @throws InvalidArgumentException If the field is missing and $throwIfMissing is true.
     */
    public function getField(string $field, bool $throwIfMissing = false): mixed
    {
        if (!array_key_exists($field, $this->token_data)) {
            if ($throwIfMissing) {
                throw new InvalidArgumentException(sprintf(self::ERROR_MISSING_FIELD, $field));
            }
            return null;
        }
        return $this->token_data[$field];
    }

    /**
     * Adds a field to the token data (JWT payload).
     * Ensures that the key is unique and the value is a valid type (scalar or array).
     *
     * @param string $key The key of the field to add.
     * @param mixed $value The value to associate with the key (must be scalar or array).
     * @return self Returns the instance to allow method chaining.
     * @throws InvalidArgumentException If the key is not unique or the value type is invalid.
     */
    public function addField(string $key, mixed $value): self
    {
        if (!is_scalar($value) && !is_array($value)) {
            throw new InvalidArgumentException(self::ERROR_INVALID_FIELD_TYPE);
        }

        if ($this->hasField($key)) {
            throw new InvalidArgumentException(self::ERROR_NOT_UNIQUE);
        }

        $this->token_data[$key] = $value;
        return $this;
    }

    /**
     * Validates that the required fields are present in the JWT payload.
     * Also checks the consistency of temporal claims (e.g., "iat", "nbf", "exp").
     *
     * @throws InvalidArgumentException If required fields are missing or temporal claims are invalid.
     */
    public function validate(): void
    {
        $requiredFields = ['exp', 'iss', 'aud']; // Required JWT claims
        foreach ($requiredFields as $field) {
            if (!$this->hasField($field)) {
                throw new InvalidArgumentException(sprintf(self::ERROR_MISSING_FIELD, $field));
            }
        }

        // Validate temporal claims (iat, nbf, exp)
        $this->validateTemporalClaims();
    }

    /**
     * Converts the token data (JWT payload) into an array.
     * Before returning the array, it validates the data.
     *
     * @return array The complete JWT payload as an associative array.
     * @throws InvalidArgumentException If validation fails.
     */
    public function toArray(): array
    {
        $this->validate();
        return $this->completeData();
    }

    /**
     * Validates the consistency of the temporal claims ("iat", "nbf", "exp").
     * Ensures that "iat" is earlier than "exp", and that "nbf" falls within the valid time range.
     *
     * @throws InvalidArgumentException If the temporal claims are inconsistent.
     */
    private function validateTemporalClaims(): void
    {
        $iat = $this->getField('iat');  // Issued At
        $nbf = $this->getField('nbf');  // Not Before
        $exp = $this->getField('exp');  // Expiration

        // Check if "iat" is earlier than "exp"
        if ($iat && $exp && $iat > $exp) {
            throw new InvalidArgumentException(self::INVALID_TOKEN_IAT_TO_EARLY);
        }

        // Check if "nbf" is earlier than "exp"
        if ($nbf && $exp && $nbf > $exp) {
            throw new InvalidArgumentException(self::INVALID_TOKEN_NBF_TO_EARLY);
        }

        // Check if "nbf" is later than or equal to "iat"
        if ($iat && $nbf && $nbf < $iat) {
            throw new InvalidArgumentException(self::INVALID_TOKEN_NBF_EARLY_IAT);
        }
    }

    /**
     * Checks whether a specific field exists in the token data (JWT payload).
     *
     * @param string $field The field to check.
     * @return bool Returns true if the field exists, false otherwise.
     */
    private function hasField(string $field): bool
    {
        return array_key_exists($field, $this->token_data);
    }

    /**
     * Completes the token data by adding missing default fields.
     * Automatically sets the "iat" field if it is not already set.
     *
     * @return array The complete JWT payload with defaults applied.
     */
    private function completeData(): array
    {
        $data = $this->token_data;

        if (!array_key_exists('iat', $data)) {
            $data['iat'] = time();
        }

        return $data;
    }

    /**
     * Parses and sets a timestamp field in the JWT payload.
     * Converts a datetime string into a Unix timestamp and stores it under the specified key.
     *
     * @param string $key The key for the timestamp field (e.g., "iat", "nbf", "exp").
     * @param string $dateTime The datetime string to be converted into a timestamp.
     * @throws InvalidArgumentException If the datetime string is in an invalid format.
     */
    private function setTimestamp(string $key, string $dateTime): void
    {
        $dateTimeImmutable = $this->dateTimeImmutable->modify($dateTime);
        if (!$dateTimeImmutable) {
            throw new InvalidArgumentException(self::ERROR_DATE_FORMAT);
        }

        $this->addField($key, $dateTimeImmutable->getTimestamp());
    }
}
