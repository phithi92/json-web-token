<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Algorithm;

use OpenSSLAsymmetricKey;
use Phithi92\JsonWebToken\Config\DefaultAlgorithmConfiguration;
use Phithi92\JsonWebToken\Interfaces\AlgorithmConfigurationInterface;
use Phithi92\JsonWebToken\Security\KeyStore;
use Phithi92\JsonWebToken\Security\PassphraseStore;

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
 */
final class JwtAlgorithmManager
{
    /**
     * Stores private and public keys in memory.
     */
    private readonly KeyStore $keyStore;

    /**
     * Stores optional passphrases for private keys.
     *
     * @var PassphraseStore
     */
    private readonly PassphraseStore $passphraseStore;

    /**
     * Holds the configuration registry for supported algorithms.
     *
     * @var AlgorithmConfigurationInterface
     */
    private readonly AlgorithmConfigurationInterface $algorithmRegistry;

    /**
     * JwtAlgorithmManager constructor.
     *
     * Initializes the algorithm configuration, key store and passphrase store.
     * If no custom configuration or stores are provided, default implementations are used.
     */
    public function __construct(
        ?AlgorithmConfigurationInterface $algConfig = null,
        ?KeyStore $keyStore = null,
        ?PassphraseStore $passphraseStore = null,
    ) {
        $this->algorithmRegistry = $algConfig ?? new DefaultAlgorithmConfiguration();
        $this->keyStore = $keyStore ?? new KeyStore();
        $this->passphraseStore = $passphraseStore ?? new PassphraseStore();
    }

    /**
     * Returns the configuration for the given algorithm identifier.
     *
     * The configuration may contain information such as algorithm type,
     * key requirements, supported key types, and handler classes.
     *
     * @param string $algorithm The algorithm identifier (e.g. "HS256", "RS256").
     *
     * @return array<string, string|array<string, string|class-string<object>>>
     */
    public function getConfiguration(string $algorithm): array
    {
        return $this->algorithmRegistry->get($algorithm);
    }

    /**
     * Checks whether a private key exists for the given key ID.
     *
     * @param string $kid The key identifier.
     *
     * @return bool True if a private key is registered, false otherwise.
     */
    public function hasPrivateKey(string $kid): bool
    {
        return $this->keyStore->hasKey($kid, 'private');
    }

    /**
     * Registers a private key in PEM format for the given key ID.
     *
     * If no key ID is provided, the implementation may generate or infer one.
     *
     * @param string      $pemContent The private key in PEM format.
     * @param string|null $kid        Optional key identifier.
     */
    public function addPrivateKey(string $pemContent, ?string $kid = null): void
    {
        $this->keyStore->addKey($pemContent, 'private', $kid);
    }

    /**
     * Registers a public key in PEM format for the given key ID.
     *
     * If no key ID is provided, the implementation may generate or infer one.
     *
     * @param string      $pemContent The public key in PEM format.
     * @param string|null $kid        Optional key identifier.
     */
    public function addPublicKey(string $pemContent, ?string $kid = null): void
    {
        $this->keyStore->addKey($pemContent, 'public', $kid);
    }

    /**
     * Checks whether a public key exists for the given key ID.
     *
     * @param string $kid The key identifier.
     *
     * @return bool True if a public key is registered, false otherwise.
     */
    public function hasPublicKey(string $kid): bool
    {
        return $this->keyStore->hasKey($kid, 'public');
    }

    /**
     * Registers both a private and a public key as a key pair.
     *
     * Both keys will be associated with the same key ID, if provided.
     *
     * @param string      $private The private key in PEM format.
     * @param string      $public  The public key in PEM format.
     * @param string|null $kid     Optional key identifier.
     */
    public function addKeyPair(string $private, string $public, ?string $kid = null): void
    {
        $this->addPrivateKey($private, $kid);
        $this->addPublicKey($public, $kid);
    }

    /**
     * Determines whether both a public and a private key exist for the given key ID.
     *
     * @param string $kid The key identifier to check.
     *
     * @return bool True if both public and private keys are stored for the given ID, false otherwise.
     */
    public function hasKeyPair(string $kid): bool
    {
        return $this->hasPublicKey($kid) && $this->hasPrivateKey($kid);
    }

    /**
     * Checks whether any key (public or private) exists for the given key ID.
     *
     * @param string $kid The key identifier.
     *
     * @return bool True if at least one key exists, false otherwise.
     */
    public function hasKey(string $kid): bool
    {
        return $this->keyStore->hasKey($kid);
    }

    /**
     * Retrieves the private key associated with the given key ID.
     *
     * @param string $kid The key identifier.
     *
     * @return OpenSSLAsymmetricKey The private key resource.
     */
    public function getPrivateKey(string $kid): OpenSSLAsymmetricKey
    {
        return $this->keyStore->getKey($kid, 'private');
    }

    /**
     * Retrieves the public key associated with the given key ID.
     *
     * @param string $kid The key identifier.
     *
     * @return OpenSSLAsymmetricKey The public key resource.
     */
    public function getPublicKey(string $kid): OpenSSLAsymmetricKey
    {
        return $this->keyStore->getKey($kid, 'public');
    }

    /**
     * Returns detailed metadata for a stored key.
     *
     * Metadata may include the original PEM string, key size in bits,
     * key type (e.g. "RSA"), the role (public/private) and the key resource.
     *
     * @param string $kid  The key identifier.
     * @param string $role The key role ("public" or "private").
     *
     * @return array{
     *     pem: string,
     *     bits: int,
     *     type: string,
     *     role: string,
     *     key: OpenSSLAsymmetricKey
     * }
     */
    public function getKeyMetadata(string $kid, string $role): array
    {
        return $this->keyStore->getMetadata($kid, $role);
    }

    /**
     * Checks whether a passphrase is registered for the given key ID.
     *
     * @param string $kid The key identifier.
     *
     * @return bool True if a passphrase exists, false otherwise.
     */
    public function hasPassphrase(string $kid): bool
    {
        return $this->passphraseStore->hasPassphrase($kid);
    }

    /**
     * Registers a passphrase for use with a private key.
     *
     * The passphrase can be associated with a specific key ID or stored
     * under a default or internally generated identifier.
     *
     * @param string      $passphrase The passphrase for the private key.
     * @param string|null $kid        Optional key identifier.
     */
    public function addPassphrase(string $passphrase, ?string $kid = null): void
    {
        $this->passphraseStore->addPassphrase($passphrase, $kid);
    }

    /**
     * Retrieves the passphrase associated with the given key ID.
     *
     * @param string $kid The key identifier.
     *
     * @return string The stored passphrase.
     */
    public function getPassphrase(string $kid): string
    {
        return $this->passphraseStore->getPassphrase($kid);
    }
}
