<?php

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Utilities\JsonEncoder;

/**
 * Represents the header of a JWT (JSON Web Token).
 *
 * The JwtHeader class encapsulates metadata about the token, including its type,
 * the algorithm used for signing or encryption, and the encryption method, if applicable.
 * It provides methods to set and retrieve these properties, ensuring consistency with
 * JWT standards.
 *
 * The class allows initialization via a JwtAlgorithmManager instance, which sets the
 * appropriate algorithm and token type based on the manager's configuration.
 *
 * @package json-web-token
 * @author Phillip Thiele <development@phillip-thiele.de>
 * @version 1.0.0
 * @since 1.0.0
 * @license https://github.com/phithi92/json-web-token/blob/main/LICENSE MIT License
 * @link https://github.com/phithi92/json-web-token Project on GitHub
 */
final class JwtHeader
{
    // The type of token, typically 'JWT' or 'JWS'
    private string $typ;

    // The algorithm used for encoding or signing the token
    private string $algorithm;

    // The encryption method used, if applicable
    private string $enc;

    /**
     * Initializes the JWT header with optional parameters for algorithm and type.
     *
     * If an algorithm or type is provided, it sets these values during instantiation.
     *
     * @param string|null $algorithm Optional algorithm identifier, e.g., 'HS256'.
     * @param string|null $type      Optional type of the token, e.g., 'JWT' or 'JWS'.
     */
    public function __construct(string $algorithm = null, string $type = null)
    {
        if (empty($algorithm) === false) {
            $this->setAlgorithm($algorithm);
        }

        if (empty($type) === false) {
            $this->setType($type);
        }
    }

    /**
     * Sets the token type in the header.
     *
     * @param  string $type The type of the token, e.g., 'JWT' or 'JWS'.
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
     * @param  string $algorithm The algorithm identifier, e.g., 'HS256'.
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
     * @param  string $enc The encryption method identifier.
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
     * Includes 'alg' (algorithm) and 'typ' (type) fields. Adds 'enc' (encryption) if present.
     *
     * @return array The associative array representation of the header.
     */
    public function toArray(): array
    {
        $header = [
            'alg' => $this->getAlgorithm(),
            'typ' => $this->getType(),
        ];

        if (empty($this->getEnc()) === false) {
            $header['enc'] = $this->getEnc();
        }

        return $header;
    }

    /**
     * Converts the JWT header to a JSON-encoded string.
     *
     * Uses JsonEncoder to transform the header array into JSON format.
     *
     * @return string The JSON-encoded representation of the header.
     * @throws DecodingException If JSON encoding fails.
     */
    public function toJson(): string
    {
        return JsonEncoder::encode($this->toArray());
    }

    /**
     * Creates a JwtHeader instance from a JSON-encoded string.
     *
     * Parses the JSON string, assigns values to the header properties, and returns a populated instance.
     *
     * @param  string $json The JSON-encoded header string.
     * @return self   A new instance of JwtHeader with populated fields.
     * @throws DecodingException If JSON decoding fails or data is invalid.
     */
    public static function fromJson(string $json): self
    {
        $header = JsonEncoder::decode($json);

        $instance = new self();

        if (isset($header->enc)) {
            $instance->setEnc($header->enc);
        }

        if (isset($header->alg)) {
            $instance->setAlgorithm($header->alg);
        }
        if (isset($header->typ)) {
            $instance->setType($header->typ);
        }

        return $instance;
    }
}
