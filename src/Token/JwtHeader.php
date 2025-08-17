<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token;

use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidKidFormatException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidKidLengthException;
use Phithi92\JsonWebToken\Exceptions\Token\MissingTokenPart;
use Phithi92\JsonWebToken\Handler\HandlerInvoker;

/**
 * Represents the header of a JWT (JSON Web Token).
 *
 * The JwtHeader class encapsulates metadata about the token, including its type,
 * the algorithm used for signing or encryption, and the encryption method, if applicable.
 * It provides methods to set and retrieve these properties, ensuring consistency with
 * JWT standards.
 */
final class JwtHeader
{
    // Min/Max length for KID validation
    private const MIN_KID_LENGTH = 3;
    private const MAX_KID_LENGTH = 64;

    private const HEADER_MAP = [
        'alg' => 'setAlgorithm',
        'typ' => 'setType',
        'enc' => 'setEnc',
        'kid' => 'setKid',
    ];

    // The type of token, typically 'JWT' or 'JWS'
    private ?string $typ = null;

    // The algorithm used for encoding or signing the token
    private ?string $algorithm = null;

    // The encryption method used, if applicable
    private ?string $enc = null;

    // The key identifier, used to indicate which key was used to sign or encrypt the token
    private ?string $kid = null;

    /**
     * Sets the Key ID ('kid') for the JWT header.
     *
     * Validates that the provided Key ID:
     * - Consists only of alphanumeric characters, dashes (`-`), or underscores (`_`).
     * - Falls within the allowed length range (3 to 64 characters).
     *
     * If the format or length of the Key ID is invalid, an exception is thrown.
     *
     * @param string $kid The Key ID to set.
     *
     * @return self                    Returns the instance for method chaining.
     *
     * @throws InvalidKidFormatException If the Key ID contains invalid characters.
     * @throws InvalidKidLengthException If the Key ID is shorter than 3 or longer than 64 characters.
     */
    public function setKid(string $kid): self
    {
        // Ensure `kid` contains only alphanumeric characters, hyphens, and underscores
        $this->assertValidKid($kid);

        $this->kid = $kid;
        return $this;
    }

    /**
     * Retrieves the kid (key id) from the header.
     *
     * @return string The token type if set.
     *
     * @throw KidNotSetException when kid is not set
     */
    public function getKid(): string
    {
        return $this->kid ?? throw new MissingTokenPart('Kid');
    }

    public function hasKid(): bool
    {
        return is_string($this->kid);
    }

    /**
     * Sets the token type in the header.
     *
     * @param string $type The type of the token, e.g., 'JWT' or 'JWS'.
     *
     * @return self   Returns the instance to allow method chaining.
     */
    public function setType(string $type): self
    {
        $this->typ = $type;
        return $this;
    }

    /**
     * Retrieves the token type from the header.
     *
     * @return string|null The token type if set, otherwise null.
     */
    public function getType(): ?string
    {
        return $this->typ;
    }

    /**
     * Sets the algorithm used for signing or encoding the token.
     *
     * @param string $algorithm The algorithm identifier, e.g., 'HS256'.
     *
     * @return self   Returns the instance to allow method chaining.
     */
    public function setAlgorithm(string $algorithm): self
    {
        $this->algorithm = $algorithm;
        return $this;
    }

    /**
     * Retrieves the algorithm identifier from the header.
     *
     * @return string|null The algorithm if set, otherwise null.
     */
    public function getAlgorithm(): ?string
    {
        return $this->algorithm;
    }

    /**
     * Sets the encryption method identifier in the header.
     *
     * @param string $enc The encryption method identifier.
     *
     * @return self   Returns the instance to allow method chaining.
     */
    public function setEnc(string $enc): self
    {
        $this->enc = $enc;
        return $this;
    }

    /**
     * Retrieves the encryption method identifier from the header.
     *
     * @return string|null The encryption method if set, otherwise null.
     */
    public function getEnc(): ?string
    {
        return $this->enc;
    }

    /**
     * Converts the JWT header to an associative array.
     *
     * Includes 'alg' (algorithm) and 'typ' (type) fields. Adds 'enc' (encryption) if present,
     * as well as 'kid' (Key ID) if it is set. The 'kid' field identifies the key used for signing or encryption.
     *
     * @return array<string,string> The associative array representation of the header.
     */
    public function toArray(): array
    {
        return array_filter(
            [
                'alg' => $this->algorithm,
                'typ' => $this->typ,
                'enc' => $this->enc,
                'kid' => $this->kid,
            ],
            static fn ($value) => $value !== null && $value !== ''
        );
    }

    /**
     * @param array<mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $invoker = new HandlerInvoker();
        $instance = new self();

        $headerFields = self::extractValidHeaderFields($data);

        foreach (self::HEADER_MAP as $jsonKey => $setter) {
            if (isset($headerFields[$jsonKey])) {
                $invoker->invoke($instance, $setter, [$headerFields[$jsonKey]]);
            }
        }

        return $instance;
    }

    /**
     * @throws InvalidKidFormatException
     * @throws InvalidKidLengthException
     */
    private function assertValidKid(string $kid): void
    {
        // validate `kid` length
        if (! $this->isValidKidLength($kid)) {
            throw new InvalidKidLengthException(self::MIN_KID_LENGTH, self::MAX_KID_LENGTH);
        }

        // Ensure `kid` contains only alphanumeric characters, hyphens, and underscores
        if (! $this->isKidFormatValid($kid)) {
            throw new InvalidKidFormatException();
        }
    }

    private function isValidKidLength(string $kid): bool
    {
        $kidLength = strlen($kid);

        return $kidLength >= self::MIN_KID_LENGTH && $kidLength <= self::MAX_KID_LENGTH;
    }

    private function isKidFormatValid(string $kid): bool
    {
        return preg_match('/^[a-zA-Z0-9._-]+$/', $kid) === 1;
    }

    /**
     * @param array<mixed> $data
     *
     * @return array<string,string>
     *
     * @throws InvalidFormatException
     */
    private static function extractValidHeaderFields(array $data): array
    {
        $allowedKeys = array_keys(self::HEADER_MAP);

        $filtered = [];

        foreach ($allowedKeys as $key) {
            if (! isset($data[$key])) {
                continue;
            }

            $value = $data[$key];

            if (! is_string($value)) {
                throw new InvalidFormatException("Header field '{$key}' must be a string.");
            }

            $filtered[$key] = $value;
        }

        return $filtered;
    }
}
