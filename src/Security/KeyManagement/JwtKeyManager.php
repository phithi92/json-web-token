<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Security\KeyManagement;

use OpenSSLAsymmetricKey;
use Phithi92\JsonWebToken\Config\Provider\AlgorithmConfigurationProvider;
use Phithi92\JsonWebToken\Config\Provider\PhpFileAlgorithmConfigurationProvider;
use Phithi92\JsonWebToken\Security\KeyEntry;
use Phithi92\JsonWebToken\Security\KeyIdentifier;
use Phithi92\JsonWebToken\Security\KeyRole;
use Phithi92\JsonWebToken\Security\KeyStore;
use Phithi92\JsonWebToken\Security\PassphraseStore;
use SensitiveParameter;

/**
 * Manages JWT cryptographic keys and related metadata.
 *
 * Responsibilities:
 * - Registering public/private keys
 * - Automatically deriving RFC 7638–compliant key identifiers (kid)
 * - Ensuring consistent kid usage across key pairs
 * - Providing access to keys, metadata and passphrases
 *
 * This class intentionally does NOT implement cryptographic standards itself.
 * All standard logic (RFC 7638, JWK thumbprints) is delegated to KeyIdentifier.
 */
final class JwtKeyManager
{
    /**
     * Stores public and private keys.
     */
    private readonly KeyStore $keyStore;

    /**
     * Stores optional passphrases for private keys.
     */
    private readonly PassphraseStore $passphraseStore;

    /**
     * Provides algorithm configuration metadata.
     */
    private readonly AlgorithmConfigurationProvider $algorithmRegistry;

    public function __construct(
        ?AlgorithmConfigurationProvider $algConfig = null,
        ?KeyStore $keyStore = null,
        ?PassphraseStore $passphraseStore = null,
    ) {
        $this->algorithmRegistry = $algConfig ?? new PhpFileAlgorithmConfigurationProvider();
        $this->keyStore = $keyStore ?? new KeyStore();
        $this->passphraseStore = $passphraseStore ?? new PassphraseStore();
    }

    /**
     * Returns the configuration for a given JWT algorithm.
     *
     * @return array<string,mixed>
     */
    public function getConfiguration(string $algorithm): array
    {
        return $this->algorithmRegistry->get($algorithm);
    }

    /**
     * Registers a private key.
     *
     * If no key identifier is provided, a RFC 7638–compliant kid
     * is automatically derived from the key material.
     */
    public function addPrivateKey(
        #[SensitiveParameter]
        string $pemContent,
        ?string $kid = null
    ): void {
        $kid ??= KeyIdentifier::fromPem($pemContent);
        $this->keyStore->addKey($pemContent, KeyRole::Private, $kid);
    }

    /**
     * Registers a public key.
     *
     * If no key identifier is provided, a RFC 7638–compliant kid
     * is automatically derived from the key material.
     */
    public function addPublicKey(
        #[SensitiveParameter]
        string $pemContent,
        ?string $kid = null
    ): void {
        $kid ??= KeyIdentifier::fromPem($pemContent);
        $this->keyStore->addKey($pemContent, KeyRole::Public, $kid);
    }

    /**
     * Registers a public/private key pair under a shared key identifier.
     *
     * If no kid is provided, it is derived once from the private key
     * to guarantee consistency.
     */
    public function addKeyPair(
        #[SensitiveParameter]
        string $private,
        #[SensitiveParameter]
        string $public,
        ?string $kid = null
    ): void {
        $kid ??= KeyIdentifier::fromPem($private);

        $this->keyStore->addKey($private, KeyRole::Private, $kid);
        $this->keyStore->addKey($public, KeyRole::Public, $kid);
    }

    /**
     * Checks whether any key exists for the given key identifier.
     */
    public function hasKey(string $kid): bool
    {
        return $this->keyStore->hasKey($kid);
    }

    /**
     * Checks whether both public and private keys exist for the given kid.
     */
    public function hasKeyPair(string $kid): bool
    {
        return $this->keyStore->hasKey($kid, KeyRole::Public)
            && $this->keyStore->hasKey($kid, KeyRole::Private);
    }

    /**
     * Returns the private key for the given key identifier.
     */
    public function getPrivateKey(string $kid): OpenSSLAsymmetricKey
    {
        return $this->keyStore->getKey($kid, KeyRole::Private);
    }

    /**
     * Returns the public key for the given key identifier.
     */
    public function getPublicKey(string $kid): OpenSSLAsymmetricKey
    {
        return $this->keyStore->getKey($kid, KeyRole::Public);
    }

    /**
     * Returns detailed metadata for a stored key.
     */
    public function getKeyMetadata(string $kid, KeyRole $role): KeyEntry
    {
        return $this->keyStore->getMetadata($kid, $role);
    }

    /**
     * Registers a passphrase for a private key.
     */
    public function addPassphrase(
        #[SensitiveParameter]
        string $passphrase,
        ?string $kid = null
    ): void {
        $this->passphraseStore->addPassphrase($passphrase, $kid);
    }

    /**
     * Checks whether a passphrase exists for the given key identifier.
     */
    public function hasPassphrase(string $kid): bool
    {
        return $this->passphraseStore->hasPassphrase($kid);
    }

    /**
     * Returns the passphrase associated with the given key identifier.
     */
    public function getPassphrase(string $kid): string
    {
        return $this->passphraseStore->getPassphrase($kid);
    }
}
