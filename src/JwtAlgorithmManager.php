<?php

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Exceptions\Crypto\MissingKeysException;
use Phithi92\JsonWebToken\Exceptions\Crypto\MissingPassphraseException;
use Phithi92\JsonWebToken\Exceptions\Crypto\InvalidAsymmetricKeyException;
use Phithi92\JsonWebToken\Exceptions\Crypto\UnsupportedAlgorithmException;
use Phithi92\JsonWebToken\Interfaces\JwtAlgorithmManagerInterface;
use Phithi92\JsonWebToken\Interfaces\AlgorithmConfigurationInterface;
use Phithi92\JsonWebToken\Config\DefaultAlgorithmConfiguration;
use OpenSSLAsymmetricKey;
use SensitiveParameter;

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
 * @author  Phillip Thiele <development@phillip-thiele.de>
 * @link    https://github.com/phithi92/json-web-token Project on GitHub
 */
final class JwtAlgorithmManager implements JwtAlgorithmManagerInterface
{
    // The algorithm name (e.g., HS256, RS256, RSA-OAEP)
    private string $algorithm;

    // The configuration for given algorithm
    /** @var array<string,array<string,string>> */
    private array $config;

    // The passphrase for symmetric algorithms (optional)
    private readonly ?string $passphrase;

    // The public key for asymmetric algorithms (optional)
    private readonly ?OpenSSLAsymmetricKey $publicKey;

    // The private key for asymmetric algorithms (optional)
    private readonly ?OpenSSLAsymmetricKey $privateKey;

    // The configurations of supported algorithms
    private readonly AlgorithmConfigurationInterface $algorithmRegistry;

    /**
     * Initializes the key manager for symmetric or asymmetric algorithms.
     *
     * Handles required key material (passphrase, public/private key) depending on the algorithm type.
     *
     * @param string        $algorithm  Algorithm name (e.g. HS256, RS256, RSA-OAEP).
     * @param string|null   $passphrase Passphrase for symmetric algorithms (e.g. HMAC, PBES2).
     * @param string|null   $public     Public key for asymmetric algorithms (e.g. RSA, ECDSA).
     * @param string|null   $private    Private key for asymmetric algorithms.
     * @param AlgorithmConfigurationInterface|null $config Optional algorithm-specific configuration.
     *
     * @throws MissingPassphraseException         If a symmetric algorithm is used without passphrase.
     * @throws MissingKeysException               If an asymmetric algorithm lacks required keys.
     * @throws UnsupportedAlgorithmException      If the algorithm is not recognized or allowed.
     */
    public function __construct(
        string $algorithm = null,
        #[SensitiveParameter] ?string $passphrase = null,
        #[SensitiveParameter] ?string $public = null,
        #[SensitiveParameter] ?string $private = null,
        ?AlgorithmConfigurationInterface $config = null
    ) {
        $this->algorithmRegistry = $config ?? new DefaultAlgorithmConfiguration();

        if ($algorithm !== null) {
            $this->setAlgorithm($algorithm);
        }

        $this->validateKeys($passphrase, $public, $private);

        $publicKey = $privateKey = null;

        if ($passphrase === null) {
            $publicKey = $this->validatePublicKey($public);
            $privateKey = $this->validatePrivateKey($private);
        }

        $this->passphrase = $passphrase;
        $this->publicKey = $publicKey;
        $this->privateKey = $privateKey;
    }

    /**
     *
     * @return AlgorithmConfigurationInterface
     */
    public function getAlgorithmConfiguration(): AlgorithmConfigurationInterface
    {
        return $this->algorithmRegistry;
    }

    public function setAlgorithm(string $algorithm): self
    {
        $config = $this->algorithmRegistry->get($algorithm);
        if ($config === []) {
            throw new UnsupportedAlgorithmException($algorithm);
        }

        $this->algorithm = $algorithm;
        $this->config = $config;

        return $this;
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
     * @return array<string, string|array<string, string|class-string<object>>>
     */
    public function getConfiguration(): array
    {
        return $this->config;
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
     * @return OpenSSLAsymmetricKey|null The public key, if available.
     */
    public function getPublicKey(): ?OpenSSLAsymmetricKey
    {
        return $this->publicKey ?? null;
    }

    /**
     * Gets the private key for asymmetric algorithms.
     *
     * @return OpenSSLAsymmetricKey|null The private key, if available.
     */
    public function getPrivateKey(): ?OpenSSLAsymmetricKey
    {
        return $this->privateKey ?? null;
    }

    /**
     * Sets the public key for encryption.
     *
     * This method loads and validates the provided public key.
     * If the key is invalid, it throws an InvalidArgument exception.
     *
     * @param  string $publicKey The public key to be set.
     * @return OpenSSLAsymmetricKey
     * @throws InvalidAsymmetricKeyException If the public key is invalid.
     */
    private function validatePublicKey(#[SensitiveParameter] string $publicKey): OpenSSLAsymmetricKey
    {
        $keyResource = @openssl_pkey_get_public($publicKey);

        // Check if the key was successfully loaded
        if ($keyResource === false) {
            throw new InvalidAsymmetricKeyException();
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
     * @throws InvalidAsymmetricKeyException If the private key is invalid.
     */
    private function validatePrivateKey(#[SensitiveParameter] string $privateKey): OpenSSLAsymmetricKey
    {
        $keyResource = @openssl_pkey_get_private($privateKey);

        // Check if the key was successfully loaded
        if ($keyResource === false) {
            throw new InvalidAsymmetricKeyException();
        }

        return $keyResource;
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
        #[SensitiveParameter] ?string $passphrase,
        #[SensitiveParameter] ?string $publicKey,
        #[SensitiveParameter] ?string $privateKey
    ): void {
        if (empty($passphrase) && $publicKey === null && $privateKey === null) {
            throw new MissingPassphraseException();
        }

        if (empty($passphrase) && ($publicKey === null || $privateKey === null)) {
            throw new MissingKeysException();
        }
    }
}
