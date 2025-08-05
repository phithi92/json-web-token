<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Security;

use OpenSSLAsymmetricKey;
use RuntimeException;
use SensitiveParameter;

final class KeyStore
{
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
        string|array|null $kid = null
    ): string {
        $parsed = $this->parsePemKey($pem, $role);
        $resolvedRole = ($role ?? $parsed['role']);

        $kids = match (true) {
            is_string($kid) => [$kid],
            is_array($kid) => $kid,
            default => [KeyIdentifier::fromPem($pem)],
        };

        // insert all ids
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

    public function getKey(#[\SensitiveParameter] string $kid, string $role): OpenSSLAsymmetricKey
    {
        if (! isset($this->keys[$kid][$role])) {
            throw new RuntimeException("Key [{$kid}:{$role}] not found.");
        }

        return $this->keys[$kid][$role]['key'];
    }

    public function getType(#[\SensitiveParameter] string $kid, string $role): string
    {
        return $this->keys[$kid][$role]['type'] ?? throw new RuntimeException("Key [{$kid}:{$role}] not found.");
    }

    /**
     * @return array{pem: string, bits: int, type: string, role: string, key: OpenSSLAsymmetricKey}
     *
     * @throws RuntimeException
     */
    public function getMetadata(#[\SensitiveParameter] string $kid, ?string $role): array
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

    public function hasKey(#[\SensitiveParameter] string $kid, ?string $role = null): bool
    {
        if ($role === null) {
            return isset($this->keys[$kid]);
        }

        return isset($this->keys[$kid][$role]);
    }

    /**
     * Erkennt Typ und Rolle eines PEM-Keys und gibt alle Infos zurück.
     *
     * @param string $pem
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
    private function parsePemKey(#[SensitiveParameter] string|OpenSSLAsymmetricKey $pem, ?string $role = null): array
    {
        $this->assertValidRole($role);

        $key = $this->extractKey($pem, $role);

        if ($role === null) {
            $role = $this->extractRole($key);
        }

        [$type,$bits,$resolvedPem] = $this->extractKeyDetails($key, $role);

        return [
            'type' => $type,
            'role' => $role,
            'key' => $key,
            'pem' => $resolvedPem,
            'bits' => $bits,
        ];
    }

    /**
     * @throws RuntimeException
     */
    private function extractKey(
        #[SensitiveParameter]
        string|OpenSSLAsymmetricKey $pem,
        ?string $role = null
    ): OpenSSLAsymmetricKey {
        if ($pem instanceof OpenSSLAsymmetricKey) {
            if ($role === null) {
                throw new RuntimeException('Role must be provided when using an OpenSSLAsymmetricKey instance.');
            }
            $key = $pem;
        } else {
            $key = $this->parseAsymmetricKey($pem, $role);

            $role ??= $this->extractRole($key);
        }

        return $key;
    }

    /**
     * @throws RuntimeException
     */
    private function parseAsymmetricKey(
        #[SensitiveParameter]
        string|OpenSSLAsymmetricKey $pem,
        ?string $role = null
    ): OpenSSLAsymmetricKey {
        $key = match ($role) {
            'private' => openssl_pkey_get_private($pem),
            'public' => openssl_pkey_get_public($pem),
            default => ($private = openssl_pkey_get_private($pem)) !== false
                ? $private
                : openssl_pkey_get_public($pem),
        };

        if (! $key instanceof OpenSSLAsymmetricKey) {
            throw new RuntimeException('Invalid PEM key – neither public nor private.');
        }

        return $key;
    }

    /**
     * @return array{string,int,string}
     *
     * @throws RuntimeException
     */
    private function extractKeyDetails(#[SensitiveParameter] OpenSSLAsymmetricKey $key, ?string $role = null): array
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

        $type = $this->getKeyType($details['type']);

        return [$type, $details['bits'], $details['key']];
    }

    private function extractRole(OpenSSLAsymmetricKey $key): string
    {
        return openssl_pkey_get_public($key) === false ? 'private' : 'public';
    }

    private function assertValidRole(?string $role): void
    {
        if ($role !== null && ! in_array($role, ['private', 'public'], true)) {
            throw new RuntimeException(sprintf('Invalid key role specified. Got "%s".', $role));
        }
    }

    private function getKeyType(int $type): string
    {
        return match ($type) {
            OPENSSL_KEYTYPE_RSA => 'rsa',
            OPENSSL_KEYTYPE_EC => 'ec',
            OPENSSL_KEYTYPE_DSA => 'dsa',
            default => throw new RuntimeException('Unknown key type: ' . $type),
        };
    }
}
