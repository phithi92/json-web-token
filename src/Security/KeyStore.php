<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Security;

use OpenSSLAsymmetricKey;
use RuntimeException;
use SensitiveParameter;

use function in_array;
use function is_array;
use function is_int;
use function is_string;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function sprintf;

final class KeyStore
{
    private const PRIVATE_ROLE = 'private';
    private const PUBLIC_ROLE = 'public';

    /**
     * @var array<string, array<string, array{
     *     pem: string,
     *     bits: int,
     *     type: string,
     *     role: string,
     *     key: OpenSSLAsymmetricKey
     * }>>
     */
    private array $keys = [];

    /**
     * @param string|array<int,string>|null $kid
     */
    public function addKey(
        #[SensitiveParameter]
        string $pem,
        ?string $role = null,
        string|array|null $kid = null,
    ): string {
        $parsed = $this->buildKeyMetadata($pem, $role);
        $resolvedRole = $role ?? $parsed['role'];

        $kids = match (true) {
            is_string($kid) => [$kid],
            is_array($kid) => $kid,
            default => [KeyIdentifier::fromPem($pem)],
        };

        foreach ($kids as $singleKid) {
            $this->keys[$singleKid][$resolvedRole] = $parsed;
        }

        return $kids[0];
    }

    /**
     * @return array<string, array<string, array{
     *     pem: string,
     *     bits: int,
     *     type: string,
     *     role: string,
     *     key: OpenSSLAsymmetricKey
     * }>>
     */
    public function getAll(): array
    {
        return $this->keys;
    }

    public function getKey(#[SensitiveParameter] string $kid, string $role): OpenSSLAsymmetricKey
    {
        if (! isset($this->keys[$kid][$role])) {
            throw new RuntimeException("Key [{$kid}:{$role}] not found.");
        }

        return $this->keys[$kid][$role]['key'];
    }

    public function getType(#[SensitiveParameter] string $kid, string $role): string
    {
        return $this->keys[$kid][$role]['type']
            ?? throw new RuntimeException("Key [{$kid}:{$role}] not found.");
    }

    /**
     * @return array{pem: string, bits: int, type: string, role: string, key: OpenSSLAsymmetricKey}
     *
     * @throws RuntimeException
     */
    public function getMetadata(#[SensitiveParameter] string $kid, string $role): array
    {
        if (! isset($this->keys[$kid])) {
            throw new RuntimeException("Key with ID [{$kid}] not found.");
        }

        $entries = $this->keys[$kid];
        if (! isset($entries[$role])) {
            throw new RuntimeException("Role [{$role}] not found for key ID [{$kid}].");
        }

        return $entries[$role];
    }

    public function hasKey(#[SensitiveParameter] string $kid, ?string $role = null): bool
    {
        if ($role === null) {
            return isset($this->keys[$kid]);
        }

        return isset($this->keys[$kid][$role]);
    }

    /**
     * Build normalized metadata for a PEM key (type, role, bits, pem, key).
     *
     * @return array{
     *      type: string,
     *      role: string,
     *      key: OpenSSLAsymmetricKey,
     *      pem: string,
     *      bits: int
     * }
     *
     * @throws RuntimeException
     */
    private function buildKeyMetadata(
        #[SensitiveParameter]
        string|OpenSSLAsymmetricKey $pem,
        ?string $role = null,
    ): array {
        $this->assertValidRole($role);

        [$resolvedKey, $resolvedRole] = $this->resolveKey($pem, $role);
        [$type, $bits, $resolvedPem] = $this->resolveKeyDetails($resolvedKey);

        return [
            'type' => $type,
            'role' => $resolvedRole,
            'key' => $resolvedKey,
            'pem' => $resolvedPem,
            'bits' => $bits,
        ];
    }

    /**
     * @return array{OpenSSLAsymmetricKey,'private'|'public'}
     *
     * @throws RuntimeException
     */
    private function resolveKey(
        #[SensitiveParameter]
        string|OpenSSLAsymmetricKey $pem,
        ?string $role = null,
    ): array {
        return match ($role) {
            self::PRIVATE_ROLE => [$this->ensureKey(openssl_pkey_get_private($pem)), self::PRIVATE_ROLE],
            self::PUBLIC_ROLE => [$this->ensureKey(openssl_pkey_get_public($pem)), self::PUBLIC_ROLE],
            default => $this->detectKeyRole($pem),
        };
    }

    private function ensureKey(OpenSSLAsymmetricKey|false $key): OpenSSLAsymmetricKey
    {
        if ($key === false) {
            throw new RuntimeException('Could not load OpenSSL key.');
        }

        return $key;
    }

    /**
     * @return array{string, int, string}
     *
     * @throws RuntimeException
     */
    private function resolveKeyDetails(#[SensitiveParameter] OpenSSLAsymmetricKey $key): array
    {
        $details = openssl_pkey_get_details($key);
        if (
            ! is_array($details)
            || ! is_int($details['type'])
            || ! is_int($details['bits'])
            || ! is_string($details['key'])
        ) {
            throw new RuntimeException('Could not determine key details.');
        }

        return [$this->mapKeyType($details['type']), $details['bits'], $details['key']];
    }

    /**
     * @return array{OpenSSLAsymmetricKey,'private'|'public'}
     */
    private function detectKeyRole(#[SensitiveParameter] OpenSSLAsymmetricKey|string $pem): array
    {
        // Try private key
        $private = openssl_pkey_get_private($pem);
        if ($private !== false) {
            return [$private, self::PRIVATE_ROLE];
        }

        // Fallback: public key
        $public = openssl_pkey_get_public($pem);
        if ($public !== false) {
            return [$public, self::PUBLIC_ROLE];
        }

        throw new RuntimeException('Could not load OpenSSL key (neither private nor public).');
    }

    private function assertValidRole(?string $role): void
    {
        if ($role !== null && ! in_array($role, [self::PRIVATE_ROLE, self::PUBLIC_ROLE], true)) {
            throw new RuntimeException(sprintf('Invalid key role specified. Got "%s".', $role));
        }
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
