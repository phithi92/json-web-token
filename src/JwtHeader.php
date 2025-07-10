<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Exceptions\Token\InvalidKidFormatException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidKidLengthException;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;

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
    // The type of token, typically 'JWT' or 'JWS'
    private string $typ;

    // The algorithm used for encoding or signing the token
    private string $algorithm;

    // The encryption method used, if applicable
    private string $enc;

    // The key identifier, used to indicate which key was used to sign or encrypt the token
    private string $kid;

    /**
     * Sets the Key ID ('kid') for the JWT header.
     *
     * Validates that the provided Key ID:
     * - Consists only of alphanumeric characters, dashes (`-`), or underscores (`_`).
     * - Falls within the allowed length range (3 to 64 characters).
     *
     * If the format or length of the Key ID is invalid, an exception is thrown.
     *
     * @param string $type The Key ID to set.
     *
     * @return self                    Returns the instance for method chaining.
     *
     * @throws InvalidKidFormatException If the Key ID contains invalid characters.
     * @throws InvalidKidLengthException If the Key ID is shorter than 3 or longer than 64 characters.
     */
    public function setKid(string $type): self
    {
        // Define min and max length constraints for the 'kid'
        $minLength = 3;
        $maxLength = 64;

        // Ensure `kid` contains only alphanumeric characters, hyphens, and underscores
        if (! ctype_alnum(str_replace(['-', '_'], '', $type))) {
            throw new InvalidKidFormatException();
        }

        if (strlen($type) < $minLength || strlen($type) > $maxLength) {
            throw new InvalidKidLengthException($minLength, $maxLength);
        }

        $this->kid = $type;
        return $this;
    }

    /**
     * Retrieves the token type from the header.
     *
     * @return string|null The token type if set, otherwise null.
     */
    public function getKid(): ?string
    {
        return $this->kid ?? null;
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
        return $this->typ ?? null;
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
        return $this->algorithm ?? null;
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
        return $this->enc ?? null;
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
                'alg' => $this->getAlgorithm(),
                'typ' => $this->getType(),
                'enc' => $this->getEnc(),
                'kid' => $this->getKid(),
            ],
            static fn ($value) => $value !== null && $value !== ''
        );
    }

    /**
     * Converts the JWT header to a JSON-encoded string.
     *
     * Uses JsonEncoder to transform the header array into JSON format.
     *
     * @return string The JSON-encoded representation of the header.
     */
    public function toJson(): string
    {
        return JsonEncoder::encode($this->toArray(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * Creates a JwtHeader instance from a JSON-encoded string.
     *
     * Parses the JSON string, assigns values to the header properties, and returns a populated instance.
     *
     * @param string $json The JSON-encoded header string.
     *
     * @return self   A new instance of JwtHeader with populated fields.
     */
    public static function fromJson(string $json): self
    {
        /** @var \stdClass $data */
        $data = JsonEncoder::decode($json, false);
        $instance = new self();

        $map = [
            'alg' => 'setAlgorithm',
            'typ' => 'setType',
            'enc' => 'setEnc',
            'kid' => 'setKid',
        ];

        foreach ($map as $jsonKey => $setter) {
            if (isset($data->$jsonKey)) {
                $instance->$setter($data->$jsonKey);
            }
        }

        return $instance;
    }
}
