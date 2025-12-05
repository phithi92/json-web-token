<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token;

use JsonSerializable;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidKidFormatException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidKidLengthException;
use Phithi92\JsonWebToken\Exceptions\Token\MissingTokenPart;
use Phithi92\JsonWebToken\Handler\HandlerInvoker;

use function array_filter;
use function array_key_exists;
use function array_keys;
use function ctype_alnum;
use function gettype;
use function is_string;
use function sprintf;
use function str_replace;
use function strlen;

/**
 * Represents the header of a JWT (JSON Web Token).
 *
 * The JwtHeader class encapsulates metadata about the token, including its type,
 * the algorithm used for signing or encryption, and the encryption method, if applicable.
 * It provides methods to set and retrieve these properties, ensuring consistency with
 * JWT standards.
 */
final class JwtHeader implements JsonSerializable
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
     * @param string $kid the Key ID to set
     *
     * @return self returns the instance for method chaining
     *
     * @throws InvalidKidFormatException if the Key ID contains invalid characters
     * @throws InvalidKidLengthException if the Key ID is shorter than 3 or longer than 64 characters
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
     * @return string the token type if set
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
     * @return self returns the instance to allow method chaining
     */
    public function setType(string $type): self
    {
        $this->typ = $type;

        return $this;
    }

    /**
     * Retrieves the token type from the header.
     *
     * @return string|null the token type if set, otherwise null
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
     * @return self returns the instance to allow method chaining
     */
    public function setAlgorithm(string $algorithm): self
    {
        $this->algorithm = $algorithm;

        return $this;
    }

    /**
     * Retrieves the algorithm identifier from the header.
     *
     * @return string|null the algorithm if set, otherwise null
     */
    public function getAlgorithm(): ?string
    {
        return $this->algorithm;
    }

    /**
     * Sets the encryption method identifier in the header.
     *
     * @param string $enc the encryption method identifier
     *
     * @return self returns the instance to allow method chaining
     */
    public function setEnc(string $enc): self
    {
        $this->enc = $enc;

        return $this;
    }

    /**
     * Retrieves the encryption method identifier from the header.
     *
     * @return string|null the encryption method if set, otherwise null
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
     * @return array<string,string> the associative array representation of the header
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
     * @return array{typ?:string, alg?:string, kid?:string, enc?:string}
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * @param array<mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $invoker = new HandlerInvoker();
        $instance = new self();

        $headerFields = self::filterStringMap($data);

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
        return ($s = str_replace(['.', '_', '-'], '', $kid)) !== '' && ctype_alnum($s);
    }

    /**
     * Filters the given data array down to allowed header keys
     * and ensures both keys and values are strings.
     *
     * @param array<mixed> $data
     *
     * @return array<string,string>
     *
     * @throws InvalidFormatException if a value is not a string
     */
    private static function filterStringMap(array $data): array
    {
        $allowedKeys = array_keys(self::HEADER_MAP);

        $filtered = [];
        foreach ($allowedKeys as $key) {
            if (! array_key_exists($key, $data)) {
                continue;
            }

            $value = $data[$key];

            if (! is_string($value)) {
                throw new InvalidFormatException(
                    sprintf(
                        "Invalid type for header key '%s': expected string, got %s",
                        $key,
                        gettype($value)
                    )
                );
            }

            $filtered[$key] = $value;
        }

        return $filtered;
    }
}
