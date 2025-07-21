<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken;

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
    private readonly KeyStore $keyStore;

    private readonly PassphraseStore $passphraseStore;

    // The configurations of supported algorithms
    private readonly AlgorithmConfigurationInterface $algorithmRegistry;

    public function __construct(
        ?AlgorithmConfigurationInterface $algConfig = null,
        ?KeyStore $keyStore = null,
        ?PassphraseStore $passphraseStore = null
    ) {
        $this->algorithmRegistry = ($algConfig ?? new DefaultAlgorithmConfiguration());
        $this->keyStore = ($keyStore ?? new KeyStore());
        $this->passphraseStore = ($passphraseStore ?? new PassphraseStore());
    }

    /**
     * @return array<string, string|array<string, string|class-string<object>>>
     */
    public function getConfiguration(string $algorithm): array
    {
        return $this->algorithmRegistry->get($algorithm);
    }

    public function hasPrivateKey(string $kid): bool
    {
        return $this->keyStore->hasKey($kid, 'private');
    }

    public function addPrivateKey(string $pemContent, ?string $kid): void
    {
        $this->keyStore->addKey($pemContent, 'private', $kid);
    }

    public function addPublicKey(string $pemContent, ?string $kid): void
    {
        $this->keyStore->addKey($pemContent, 'public', $kid);
    }

    public function hasPublicKey(string $kid): bool
    {
        return $this->keyStore->hasKey($kid, 'public');
    }

    public function hasKey(string $kid): bool
    {
        return $this->keyStore->hasKey($kid);
    }

    public function getPrivateKey(string $kid): OpenSSLAsymmetricKey
    {
        return $this->keyStore->getKey($kid, 'private');
    }

    public function getPublicKey(string $kid): OpenSSLAsymmetricKey
    {
        return $this->keyStore->getKey($kid, 'public');
    }

    /**
     * @return array{
     *     pem: string,
     *     bits: int,
     *     type: string,
     *     role: string,
     *     key: OpenSSLAsymmetricKey
     * }
     */
    public function getKeyMetadata(string $kid, ?string $role = null): array
    {
        return $this->keyStore->getMetadata($kid, $role);
    }

    public function hasPassphrase(string $kid): bool
    {
        return $this->passphraseStore->hasPassphrase($kid);
    }

    public function addPassphrase(string $passphrase, ?string $kid): void
    {
        $this->passphraseStore->addPassphrase($passphrase, $kid);
    }

    public function getPassphrase(string $kid): string
    {
        return $this->passphraseStore->getPassphrase($kid);
    }
}
