<?php

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Exception\InvalidArgument;
use Phithi92\JsonWebToken\Exception\AlgorithmManager\UnsupportedAlgorithmException;
use Phithi92\JsonWebToken\Service\SignatureToken;
use Phithi92\JsonWebToken\Service\EncodingToken;
use ReflectionClass;
use OpenSSLAsymmetricKey;

/**
 * Manages algorithms for JWT signing and encryption.
 *
 * The JwtAlgorithmManager class handles initialization and configuration
 * for JWT algorithms, supporting both symmetric (e.g., HS256) and asymmetric
 * (e.g., RS256) cryptographic operations. It manages the token type (`JWS` for signed
 * tokens or `JWE` for encrypted tokens) based on the chosen algorithm and provides
 * access to supported algorithms for each token type.
 *
 * The class uses optional passphrases or key pairs, depending on the algorithm:
 * - Symmetric algorithms require a passphrase.
 * - Asymmetric algorithms require both a public and a private key.
 *
 * This class also includes utility methods for retrieving supported algorithms
 * for JWS and JWE tokens.
 *
 * Key Properties:
 * - `$algorithm`: The algorithm name, such as 'HS256' or 'RS256'.
 * - `$tokenType`: The token type, either 'JWS' or 'JWE'.
 * - `$passphrase`: Optional passphrase for symmetric algorithms.
 * - `$publicKey` and `$privateKey`: Optional keys for asymmetric algorithms.
 *
 * Key Methods:
 * - getAlgorithm(): Returns the name of the algorithm.
 * - getTokenType(): Returns the token type (`JWS` or `JWE`).
 * - getJwsAlgorithms(): Returns an array of supported JWS algorithms.
 * - getJweAlgorithms(): Returns an array of supported JWE algorithms.
 *
 * @package json-web-token
 * @author Phillip Thiele <development@phillip-thiele.de>
 * @version 1.0.0
 * @since 1.0.0
 * @license https://github.com/phithi92/json-web-token/blob/main/LICENSE MIT License
 * @link https://github.com/phithi92/json-web-token Project on GitHub
 */
class JwtAlgorithmManager
{
    // The algorithm name (e.g., HS256, RS256, RSA-OAEP)
    private string $algorithm;

    // The type of token (either 'JWS' for signed or 'JWE' for encrypted)
    private string $tokenType;

    // The passphrase for symmetric algorithms (optional)
    private ?string $passphrase = null;

    // The public key for asymmetric algorithms (optional)
    private ?OpenSSLAsymmetricKey $publicKey = null;

    // The private key for asymmetric algorithms (optional)
    private ?OpenSSLAsymmetricKey $privateKey = null;

    // List of supported JWS algorithms
    private static array $jwsAlgorithms = [
        'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512',
        'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'
    ];

    // List of supported JWE algorithms
    private static array $jweAlgorithms = [
        'RSA-OAEP', 'RSA-OAEP-256', 'RSA1_5', 'A128GCM', 'A192GCM', 'A256GCM'
    ];

    /**
     * Constructor for symmetric or asymmetric algorithms.
     *
     * Initializes the manager with the necessary keys or passphrase based on the algorithm.
     *
     * @param string      $algorithm  The algorithm name, e.g., HS256, RS256, RSA-OAEP.
     * @param string|null $passphrase Optional passphrase for symmetric algorithms.
     * @param string|null $publicKey  Optional public key for asymmetric algorithms.
     * @param string|null $privateKey Optional private key for asymmetric algorithms.
     *
     * @throws InvalidArgument If both passphrase and keys are missing.
     */
    public function __construct(
        string $algorithm,
        ?string $passphrase = null,
        ?string $publicKey = null,
        ?string $privateKey = null
    ) {
        if ($passphrase === null && ($publicKey === null || $privateKey === null)) {
            throw new InvalidArgument('passphrase or public and private key needed');
        }

        if ($passphrase !== null) {
            $this->passphrase = $passphrase;
        } elseif ($publicKey !== null && $privateKey !== null) {
            $this->setPublicKey($publicKey);
            $this->setPrivateKey($privateKey);
        }

        $this->tokenType = $this->determineTokenType($algorithm);
        $this->algorithm = $algorithm;
    }

    /**
     * Sets the public key for encryption.
     *
     * This method loads and validates the provided public key.
     * If the key is invalid, it throws an InvalidArgument exception.
     *
     * @param string $publicKey The public key to be set.
     * @return self Returns the current instance for method chaining.
     * @throws InvalidArgument If the public key is invalid.
     */
    private function setPublicKey(string $publicKey): self
    {
        $keyResource = openssl_pkey_get_public($publicKey);

        // Check if the key was successfully loaded
        if ($keyResource === false) {
            throw new InvalidArgument('invalid public key');
        }

        $this->publicKey = $keyResource;

        return $this;
    }

    /**
     * Sets the private key for decryption.
     *
     * This method loads and validates the provided private key.
     * If the key is invalid, it throws an InvalidArgument exception.
     *
     * @param string $privateKey The private key to be set.
     * @return self Returns the current instance for method chaining.
     * @throws InvalidArgument If the private key is invalid.
     */
    private function setPrivateKey(string $privateKey): self
    {
        $keyResource = openssl_pkey_get_private($privateKey);

        // Check if the key was successfully loaded
        if ($keyResource === false) {
            throw new InvalidArgument('invalid private key');
        }

        $this->privateKey = $keyResource;

        return $this;
    }

    /**
     * Retrieves supported JWS algorithms.
     *
     * @return array An array of supported JWS algorithms.
     */
    public static function getJwsAlgorithms(): array
    {
        if (empty(self::$jwsAlgorithms)) {
            self::$jwsAlgorithms = (new ReflectionClass(SignatureToken::class))->getConstants();
        }

        return self::$jwsAlgorithms;
    }

    /**
     * Retrieves supported JWE algorithms.
     *
     * @return array An array of supported JWE algorithms.
     */
    public function getJweAlgorithms(): array
    {
        if (empty(self::$jweAlgorithms)) {
            self::$jweAlgorithms = (new ReflectionClass(EncodingToken::class))->getConstants();
        }

        return self::$jweAlgorithms;
    }

    /**
     * Determines the token type (JWS or JWE) based on the algorithm.
     *
     * Uses the list of supported algorithms to identify if the token is a JWS or JWE.
     *
     * @param  string $algorithm The algorithm used.
     * @return string The token type ('JWS' for signed or 'JWE' for encrypted).
     */
    private function determineTokenType(string $algorithm): string
    {
        if (in_array($algorithm, self::getJwsAlgorithms())) {
            return 'JWS'; // Signed token
        } elseif (in_array($algorithm, self::getJweAlgorithms())) {
            return 'JWE'; // Encrypted token
        } else {
            throw new UnsupportedAlgorithmException($algorithm);
        }
    }

    /**
     * Gets the algorithm name.
     *
     * @return string The algorithm name.
     */
    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * Gets the passphrase for symmetric algorithms.
     *
     * @return string|null The passphrase, if available.
     */
    public function getPassphrase(): ?string
    {
        return $this->passphrase;
    }

    /**
     * Gets the public key for asymmetric algorithms.
     *
     * @return string|null The public key, if available.
     */
    public function getPublicKey(): ?OpenSSLAsymmetricKey
    {
        return $this->publicKey;
    }

    /**
     * Gets the private key for asymmetric algorithms.
     *
     * @return string|null The private key, if available.
     */
    public function getPrivateKey(): ?OpenSSLAsymmetricKey
    {
        return $this->privateKey;
    }

    /**
     * Retrieves the type of token (either 'JWS' or 'JWE').
     *
     * @return string The token type.
     */
    public function getTokenType(): string
    {
        return $this->tokenType;
    }
}
