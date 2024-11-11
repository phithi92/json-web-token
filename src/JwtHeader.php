<?php

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Utilities\JsonEncoder;
use Phithi92\JsonWebToken\JwtAlgorithmManager;

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
class JwtHeader
{
    // The type of token, typically 'JWT' or 'JWS'
    private string $typ = '';

    // The algorithm used for encoding or signing the token
    private string $algorithm = '';

    // The encryption method used, if applicable
    private string $enc = '';

    /**
     * Constructor initializes the header with an optional JwtAlgorithmManager.
     *
     * Sets the algorithm and type based on the provided manager, if available.
     *
     * @param JwtAlgorithmManager|null $manager Optional manager to set the algorithm and type.
     */
    public function __construct(?string $algorithm = null, ?string $type = null)
    {
        if (
            is_string($algorithm) === true
            && empty($algorithm) === false
        ) {
            $this->setAlgorithm($algorithm);
        }

        if (
            is_string($type) === true
            && empty($type) === false
        ) {
            $this->setType($type);
        }
    }

    /**
     * Sets the token type.
     *
     * @param  string $type The type of the token, e.g., 'JWT' or 'JWS'.
     * @return self   Returns the instance for method chaining.
     */
    public function setType(string $type): self
    {
        $this->typ = $type;
        return $this;
    }

    /**
     * Retrieves the token type.
     *
     * @return string The token type.
     */
    public function getType(): string
    {
        return $this->typ;
    }

    /**
     * Sets the algorithm for the token.
     *
     * @param  string $algorithm The algorithm identifier, e.g., 'HS256'.
     * @return self   Returns the instance for method chaining.
     */
    public function setAlgorithm(string $algorithm): self
    {
        $this->algorithm = $algorithm;
        return $this;
    }

    /**
     * Retrieves the algorithm identifier.
     *
     * @return string The algorithm used for signing or encryption.
     */
    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * Sets the encryption method.
     *
     * @param  string $enc The encryption method identifier.
     * @return self   Returns the instance for method chaining.
     */
    public function setEnc(string $enc): self
    {
        $this->enc = $enc;
        return $this;
    }

    /**
     * Retrieves the encryption method.
     *
     * @return string The encryption method used, if any.
     */
    public function getEnc(): string
    {
        return $this->enc;
    }

    /**
     * Converts the header to an associative array.
     *
     * Includes the 'alg' and 'typ' fields. Adds 'enc' if the type is 'JWS'.
     *
     * @return array The associative array representation of the header.
     */
    public function toArray(): array
    {
        $header = [
            'alg' => $this->getAlgorithm(),
            'typ' => $this->getType(),
        ];

        if ($header['typ'] === 'JWS') {
            $header['enc'] = $this->getEnc();
        }

        return $header;
    }

    /**
     * Converts the header to a JSON-encoded string.
     *
     * @return string The JSON-encoded representation of the header.
     */
    public function toJson(): string
    {
        return JsonEncoder::encode($this->toArray());
    }

    /**
     * Creates a JwtHeader instance from a JSON string.
     *
     * Decodes the JSON and populates the header fields if present.
     *
     * @param  string $json The JSON-encoded header string.
     * @return self   A new instance of JwtHeader with populated fields.
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
