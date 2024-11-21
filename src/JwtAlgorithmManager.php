<?php

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Exceptions\Cryptographys\MissingKeysException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\MissingPassphraseException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\InvalidAsymetricKeyException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\UnsupportedAlgorithmException;
use OpenSSLAsymmetricKey;

/**
 * Manages JWT cryptographic operations for symmetric and asymmetric algorithms.
 *
 * This class facilitates the initialization and management of JWT algorithms,
 * supporting both symmetric (e.g., HS256) and asymmetric (e.g., RS256) cryptographic
 * operations. It provides methods to set and retrieve the necessary keys and passphrase.
 *
 * Asymmetric keys (public and private) are validated upon setting, and an
 * exception will be thrown if the keys are invalid. This validation ensures the
 * integrity and security of cryptographic operations, and prevents the use of
 * unsupported or malformed keys.
 *
 * @package Phithi92\JsonWebToken
 * @author  Phillip Thiele <development@phillip-thiele.de>
 * @version 1.0.0
 * @since   1.0.0
 * @license https://github.com/phithi92/json-web-token/blob/main/LICENSE MIT License
 * @link    https://github.com/phithi92/json-web-token Project on GitHub
 */
final class JwtAlgorithmManager
{
    // The algorithm name (e.g., HS256, RS256, RSA-OAEP)
    private readonly string $algorithm;

    // The type of token (either 'JWS' for signed or 'JWE' for encrypted)
    private string $type;

    // The passphrase for symmetric algorithms (optional)
    private readonly ?string $passphrase;

    // The public key for asymmetric algorithms (optional)
    private readonly ?OpenSSLAsymmetricKey $publicKey;

    // The private key for asymmetric algorithms (optional)
    private readonly ?OpenSSLAsymmetricKey $privateKey;

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
     * @throws MissingPassphraseException
     * @throws MissingKeysException
     */
    public function __construct(
        string $algorithm,
        string $passphrase = null,
        string $publicKey = null,
        string $privateKey = null
    ) {
        $this->validateKeys($passphrase, $publicKey, $privateKey);

        $this->algorithm = $algorithm;

        if ($passphrase === null) {
            $public = $this->validatePublicKey($publicKey);
            $private = $this->validatePrivateKey($privateKey);

            $this->publicKey = $public;
            $this->privateKey = $private;
            $this->passphrase = null;
        } else {
            $this->passphrase = $passphrase;
            $this->publicKey = null;
            $this->privateKey = null;
        }
    }

    /**
     * Gets the algorithm name.
     *
     * @return string The algorithm name.
     */
    public function getAlgorithm(): string|null
    {
        return $this->algorithm ?? null;
    }

    /**
     * Gets the passphrase for symmetric algorithms.
     *
     * @return string|null The passphrase, if available.
     */
    public function getPassphrase(): string|null
    {
        return $this->passphrase ?? null;
    }

    /**
     * Gets the public key for asymmetric algorithms.
     *
     * @return OpenSSLAsymmetricKey|null The public key, if available.
     */
    public function getPublicKey(): OpenSSLAsymmetricKey|null
    {
        return $this->publicKey ?? null;
    }

    /**
     * Gets the private key for asymmetric algorithms.
     *
     * @return OpenSSLAsymmetricKey|null The private key, if available.
     */
    public function getPrivateKey(): OpenSSLAsymmetricKey|null
    {
        return $this->privateKey ?? null;
    }

    /**
     * Retrieves the type of token (either 'JWS' or 'JWE').
     *
     * @return string The token type.
     */
    public function getTokenType(): string|null
    {
        return $this->type ?? null;
    }

    /**
     * Sets the public key for encryption.
     *
     * This method loads and validates the provided public key.
     * If the key is invalid, it throws an InvalidArgument exception.
     *
     * @param  string $publicKey The public key to be set.
     * @return OpenSSLAsymmetricKey
     * @throws InvalidAsymetricKeyException If the public key is invalid.
     */
    private function validatePublicKey(string $publicKey): OpenSSLAsymmetricKey
    {
        $keyResource = openssl_pkey_get_public($publicKey);

        // Check if the key was successfully loaded
        if ($keyResource === false) {
            throw new InvalidAsymetricKeyException();
        }

        return $keyResource;
    }

    /**
     * Sets the private key for decryption.
     *
     * This method loads and validates the provided private key.
     * If the key is invalid, it throws an InvalidArgument exception.
     *
     * @param  string $privateKey The private key to be set.
     * @return OpenSSLAsymmetricKey
     * @throws InvalidAsymetricKeyException If the private key is invalid.
     */
    private function validatePrivateKey(string $privateKey): OpenSSLAsymmetricKey
    {
        $keyResource = openssl_pkey_get_private($privateKey);

        // Check if the key was successfully loaded
        if ($keyResource === false) {
            throw new InvalidAsymetricKeyException();
        }

        return $keyResource;
    }

    /**
     * Sets the token type for the current instance.
     *
     * @param  string $type The token type to set.
     * @return self Returns the current instance for chaining.
     */
    public function setTokenType(string $type): self
    {
        $this->type = $type;
        return $this;
    }

    /**
     * Initializes cryptographic keys and passphrase for secure operations.
     *
     * This method checks that at least one of the required parameters (passphrase, public key, or private key)
     * is provided. It throws an exception if all parameters are `null` or if a public-private key pair
     * is incomplete when no passphrase is given. Depending on the parameters provided, it sets either the
     * passphrase or the public-private key pair.
     *
     * @param string|null $passphrase The passphrase for encryption/decryption operations, or `null`.
     * @param string|null $publicKey  The public key for encryption, or `null`.
     * @param string|null $privateKey The private key for decryption, or `null`.
     *
     * @throws MissingPassphraseException If all parameters are `null`.
     * @throws MissingKeysException If both a public and private key are not provided when the passphrase is `null`.
     *
     * @return void
     */
    private function validateKeys(
        ?string $passphrase,
        ?string $publicKey,
        ?string $privateKey
    ): void {
        if (empty($passphrase) && $publicKey === null && $privateKey === null) {
            throw new MissingPassphraseException();
        }

        if (empty($passphrase) && ($publicKey === null || $privateKey === null)) {
            throw new MissingKeysException();
        }
    }
}
