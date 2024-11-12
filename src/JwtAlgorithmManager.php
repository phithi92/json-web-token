<?php

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Exceptions\Cryptographys\MissingKeysException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\MissingPassphraseException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\InvalidAsymetricKeyException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\UnsupportedAlgorithmException;
use Phithi92\JsonWebToken\Processors\SignatureProcessor;
use Phithi92\JsonWebToken\Processors\EncodingProcessor;
use OpenSSLAsymmetricKey;

/**
 * Manages JWT cryptographic operations for symmetric and asymmetric algorithms.
 *
 * This class facilitates the initialization and management of JWT algorithms,
 * supporting both symmetric (e.g., HS256) and asymmetric (e.g., RS256) cryptographic
 * operations. It provides methods to set and retrieve the necessary keys and passphrase,
 * while ensuring that the selected algorithm and token type (either 'JWS' for signed tokens
 * or 'JWE' for encrypted tokens) are compatible.
 *
 * Asymmetric keys (public and private) are validated upon setting, and an
 * exception will be thrown if the keys are invalid. This validation ensures the
 * integrity and security of cryptographic operations, and prevents the use of
 * unsupported or malformed keys.
 *
 * Dependencies include SignatureProcessor and EncodingProcessor classes to verify algorithm support.
 *
 * @package json-web-token
 * @author Phillip Thiele <development@phillip-thiele.de>
 * @version 1.0.0
 * @since 1.0.0
 * @license https://github.com/phithi92/json-web-token/blob/main/LICENSE MIT License
 * @link https://github.com/phithi92/json-web-token Project on GitHub
 */
final class JwtAlgorithmManager
{
    // The algorithm name (e.g., HS256, RS256, RSA-OAEP)
    private readonly string $algorithm;

    // The type of token (either 'JWS' for signed or 'JWE' for encrypted)
    private readonly string $type;

    // The passphrase for symmetric algorithms (optional)
    private readonly string $passphrase;

    // The public key for asymmetric algorithms (optional)
    private readonly OpenSSLAsymmetricKey $publicKey;

    // The private key for asymmetric algorithms (optional)
    private readonly OpenSSLAsymmetricKey $privateKey;

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
     * @throws UnsupportedAlgorithmException
     * @throws MissingPassphraseException
     * @throws MissingKeysException
     */
    public function __construct(
        string $algorithm,
        ?string $passphrase = null,
        ?string $publicKey = null,
        ?string $privateKey = null
    ) {
        $this->initializeKeys($passphrase, $publicKey, $privateKey);
        $this->setAlgorithm($algorithm);
        $this->initializeTokenTypeAndProcessor();
    }

    /**
     * Gets the algorithm name.
     *
     * @return string The algorithm name.
     */
    public function getAlgorithm(): ?string
    {
        return $this->algorithm ?? null;
    }

    /**
     * Gets the passphrase for symmetric algorithms.
     *
     * @return string|null The passphrase, if available.
     */
    public function getPassphrase(): ?string
    {
        return $this->passphrase ?? null;
    }

    /**
     * Gets the public key for asymmetric algorithms.
     *
     * @return string|null The public key, if available.
     */
    public function getPublicKey(): ?OpenSSLAsymmetricKey
    {
        return $this->publicKey ?? null;
    }

    /**
     * Gets the private key for asymmetric algorithms.
     *
     * @return string|null The private key, if available.
     */
    public function getPrivateKey(): ?OpenSSLAsymmetricKey
    {
        return $this->privateKey ?? null;
    }

    /**
     * Retrieves the type of token (either 'JWS' or 'JWE').
     *
     * @return string The token type.
     */
    public function getTokenType(): ?string
    {
        return $this->type ?? null;
    }

    /**
     * Sets the public key for encryption.
     *
     * This method loads and validates the provided public key.
     * If the key is invalid, it throws an InvalidArgument exception.
     *
     * @param string $publicKey The public key to be set.
     * @return self Returns the current instance for method chaining.
     * @throws InvalidAsymetricKeyException If the public key is invalid.
     */
    private function setPublicKey(string $publicKey): self
    {
        $keyResource = openssl_pkey_get_public($publicKey);

        // Check if the key was successfully loaded
        if ($keyResource === false) {
            throw new InvalidAsymetricKeyException();
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
     * @throws InvalidAsymetricKeyException If the private key is invalid.
     */
    private function setPrivateKey(string $privateKey): self
    {
        $keyResource = openssl_pkey_get_private($privateKey);

        // Check if the key was successfully loaded
        if ($keyResource === false) {
            throw new InvalidAsymetricKeyException();
        }

        $this->privateKey = $keyResource;

        return $this;
    }

    /**
     * Sets the passphrase for encryption or decryption operations.
     *
     * @param string $passphrase The passphrase to set.
     * @return self Returns the current instance for chaining.
     */
    private function setPassphrase(string $passphrase): self
    {
        $this->passphrase = $passphrase;
        return $this;
    }

    /**
     * Sets the token type for the current instance.
     *
     * @param string $type The token type to set.
     * @return self Returns the current instance for chaining.
     */
    private function setTokenType(string $type): self
    {
        $this->type = $type;
        return $this;
    }

    /**
     * Sets the algorithm to be used for cryptographic operations.
     *
     * @param string $algorithm The algorithm to set.
     * @return self Returns the current instance for chaining.
     */
    private function setAlgorithm(string $algorithm): self
    {
        $this->algorithm = $algorithm;
        return $this;
    }

    /**
     * Initializes the token type based on the algorithm and sets the corresponding processor.
     *
     * Determines whether the algorithm supports JWS (JSON Web Signature) or JWE (JSON Web Encryption),
     * and sets the token type accordingly. Throws an exception if the algorithm is unsupported.
     *
     * @throws UnsupportedAlgorithmException If the algorithm is not supported.
     */
    private function initializeTokenTypeAndProcessor(): void
    {
        if (SignatureProcessor::isSupported($this->getAlgorithm())) {
            $this->setTokenType(SignatureProcessor::getTokenType());
        } elseif (EncodingProcessor::isSupported($this->getAlgorithm())) {
            $this->setTokenType(EncodingProcessor::getTokenType());
        } else {
            throw new UnsupportedAlgorithmException($this->getAlgorithm());
        }
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
     * @param string|null $publicKey The public key for encryption, or `null`.
     * @param string|null $privateKey The private key for decryption, or `null`.
     *
     * @throws MissingPassphraseException If all parameters are `null`.
     * @throws MissingKeysException If both a public and private key are not provided when the passphrase is `null`.
     *
     * @return void
     */
    private function initializeKeys(
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

        if ($passphrase === null) {
            $this->setPublicKey($publicKey);
            $this->setPrivateKey($privateKey);
        } else {
            $this->setPassphrase($passphrase);
        }
    }
}
