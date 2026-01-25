<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Security;

use OpenSSLAsymmetricKey;
use RuntimeException;
use SensitiveParameter;

use function is_array;
use function is_int;
use function is_string;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;

final class KeyStore
{
    /**
     * @var array<string, array<string, KeyEntry>>
     */
    private array $keys = [];

    /**
     * @param string|array<int,string>|null $kid
     */
    public function addKey(
        #[SensitiveParameter]
        string $pem,
        ?KeyRole $role = null,
        string|array|null $kid = null,
    ): string {
        $entry = $this->buildKeyEntry($pem, $role);
        $resolvedRole = $entry->role();

        $kids = match (true) {
            is_string($kid) => [$kid],
            is_array($kid) => $kid,
            default => [KeyIdentifier::fromPem($pem)],
        };

        foreach ($kids as $singleKid) {
            $this->keys[$singleKid][$resolvedRole->value] = $entry;
        }

        return $kids[0];
    }

    /**
     * @return array<string, array<string, KeyEntry>>
     */
    public function getAll(): array
    {
        return $this->keys;
    }

    public function getKey(string $kid, KeyRole $role): OpenSSLAsymmetricKey
    {
        if (! isset($this->keys[$kid][$role->value])) {
            throw new RuntimeException("Key [{$kid}:{$role->value}] not found.");
        }

        return $this->keys[$kid][$role->value]->key();
    }

    public function getType(string $kid, KeyRole $role): string
    {
        return $this->keys[$kid][$role->value]->type();
    }

    /**
     * @throws RuntimeException
     */
    public function getMetadata(string $kid, KeyRole $role): KeyEntry
    {
        if (! isset($this->keys[$kid])) {
            throw new RuntimeException("Key with ID [{$kid}] not found.");
        }

        $entries = $this->keys[$kid];
        if (! isset($entries[$role->value])) {
            throw new RuntimeException("Role [{$role->value}] not found for key ID [{$kid}].");
        }

        return $entries[$role->value];
    }

    public function hasKey(string $kid, ?KeyRole $role = null): bool
    {
        if ($role === null) {
            return isset($this->keys[$kid]);
        }

        return isset($this->keys[$kid][$role->value]);
    }

    /**
     * Build normalized metadata for a PEM key (type, role, bits, pem, key).
     *
     * @throws RuntimeException
     */
    private function buildKeyEntry(
        #[SensitiveParameter]
        string|OpenSSLAsymmetricKey $pem,
        ?KeyRole $role = null,
    ): KeyEntry {
        [$resolvedKey, $resolvedRole] = $this->resolveKey($pem, $role);
        [$type, $bits, $resolvedPem] = $this->resolveKeyDetails($resolvedKey, $resolvedRole);

        return new KeyEntry(
            key: $resolvedKey,
            role: $resolvedRole,
            type: $type,
            bits: $bits,
            pem: $resolvedPem
        );
    }

    /**
     * @return array{OpenSSLAsymmetricKey,KeyRole}
     *
     * @throws RuntimeException
     */
    private function resolveKey(
        #[SensitiveParameter]
        string|OpenSSLAsymmetricKey $pem,
        ?KeyRole $role = null,
    ): array {
        return match ($role) {
            KeyRole::Private => [$this->ensureKey(openssl_pkey_get_private($pem)), KeyRole::Private],
            KeyRole::Public => [$this->ensureKey(openssl_pkey_get_public($pem)), KeyRole::Public],
            default => $this->detectKeyRole($pem),
        };
    }

    private function ensureKey(
        #[SensitiveParameter]
        OpenSSLAsymmetricKey|false $key
    ): OpenSSLAsymmetricKey {
        if ($key === false) {
            throw new RuntimeException('Could not load OpenSSL key.');
        }

        return $key;
    }

    /**
     * @return array{string, int, string} [type, bits, pem]
     */
    private function resolveKeyDetails(
        #[SensitiveParameter]
        OpenSSLAsymmetricKey $key,
        KeyRole $role
    ): array {
        // Note: openssl_pkey_get_details() exposes only the public key PEM.
        // For private keys, the private PEM must be exported explicitly
        // using openssl_pkey_export().
        $details = openssl_pkey_get_details($key);

        if (! is_array($details)) {
            throw new RuntimeException('Could not determine key details.');
        }

        $type = $details['type'] ?? null;
        $bits = $details['bits'] ?? null;
        $publicPem = $details['key'] ?? null;

        if (! is_int($type) || ! is_int($bits) || ! is_string($publicPem)) {
            throw new RuntimeException('Could not determine key details.');
        }

        $mappedType = $this->mapKeyType($type);

        if ($role->value === KeyRole::Public->value) {
            return [$mappedType, $bits, $publicPem];
        }

        $privatePem = null;
        if (! openssl_pkey_export($key, $privatePem) || ! is_string($privatePem)) {
            throw new RuntimeException('Could not export private key PEM.');
        }

        return [$mappedType, $bits, $privatePem];
    }

    /**
     * @return array{OpenSSLAsymmetricKey, KeyRole}
     */
    private function detectKeyRole(#[SensitiveParameter] OpenSSLAsymmetricKey|string $pem): array
    {
        // Try private key
        $private = openssl_pkey_get_private($pem);
        if ($private !== false) {
            return [$private, KeyRole::Private];
        }

        // Fallback: public key
        $public = openssl_pkey_get_public($pem);
        if ($public !== false) {
            return [$public, KeyRole::Public];
        }

        throw new RuntimeException('Could not load OpenSSL key (neither private nor public).');
    }

    private function mapKeyType(int $type): string
    {
        return match ($type) {
            OPENSSL_KEYTYPE_RSA => 'rsa',
            OPENSSL_KEYTYPE_EC => 'ec',
            OPENSSL_KEYTYPE_DSA => 'dsa',
            default => throw new RuntimeException('Unknown key type: ' . $type),
        };
    }
}
