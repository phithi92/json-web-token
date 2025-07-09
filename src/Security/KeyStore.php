<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Security;

use OpenSSLAsymmetricKey;
use Phithi92\JsonWebToken\Interfaces\KeyStoreInterface;
use RuntimeException;

final class KeyStore implements KeyStoreInterface
{
    /**
     * @var array<string, array<string, array{key: OpenSSLAsymmetricKey, type: string}>>
     * Struktur: ['kid' => ['private' => ['key' => ..., 'type' => ...], 'public' => [...]]]
     */
    private array $keys = [];

    public function addKey(#[\SensitiveParameter] string $pem, ?string $role = null, ?string $kid = null): string
    {
        $parsed = $this->parsePemKey($pem, $role);

        $resolvedRole = $role ?? $parsed['role'];
        $resolvedKid = $kid ?? KeyIdentifier::fromPem($pem);

        $this->keys[$resolvedKid][$resolvedRole] = [
            'key' => $parsed['key'],
            'type' => $parsed['type'],
        ];

        return $resolvedKid;
    }

    public function getKey(string $kid, string $role): OpenSSLAsymmetricKey
    {
        if (! isset($this->keys[$kid][$role])) {
            throw new RuntimeException("Key [{$kid}:{$role}] not found.");
        }

        return $this->keys[$kid][$role]['key'];
    }

    public function getType(string $kid, string $role): string
    {
        return $this->keys[$kid][$role]['type'] ?? throw new RuntimeException("Key [{$kid}:{$role}] not found.");
    }

    /**
     * Gibt Key-Metadaten wie Typ (RSA, EC) und Rolle (public/private) zurück.
     *
     * @return array<string,string>
     *
     * @throws RuntimeException
     */
    public function getMetadata(string $kid): array
    {
        if (! isset($this->keys[$kid])) {
            throw new RuntimeException("Key with ID [{$kid}] not found.");
        }

        foreach ($this->keys[$kid] as $role => $data) {
            return [
                'type' => $data['type'],
                'role' => $role,
            ];
        }

        throw new RuntimeException("No roles found for key ID [{$kid}].");
    }

    public function hasKey(string $kid, ?string $role = null): bool
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
     * @return array{type: string, role: string, key: OpenSSLAsymmetricKey}
     *
     * @throws RuntimeException
     */
    private function parsePemKey(#[\SensitiveParameter] string|OpenSSLAsymmetricKey $pem, ?string $role = null): array
    {
        if ($role !== null && ! in_array($role, ['private', 'public'], true)) {
            throw new RuntimeException('Invalid key role specified. Got "' . $role . '".');
        }

        if (is_resource($pem)) {
            $key = $pem;
        } elseif ($role === 'private') {
            $key = openssl_pkey_get_private($pem);
        } elseif ($role === 'public') {
            $key = openssl_pkey_get_public($pem);
        } else {
            $key = openssl_pkey_get_private($pem);
            if ($key !== false) {
                $role = 'private';
            } else {
                $key = openssl_pkey_get_public($pem);
                $role = $key !== false ? 'public' : null;
            }
        }

        if (! $key instanceof OpenSSLAsymmetricKey || $role === null) {
            throw new RuntimeException('Invalid PEM key – neither public nor private.');
        }

        $details = openssl_pkey_get_details($key);
        if (! $details || ! isset($details['type'])) {
            throw new RuntimeException('Could not determine key type.');
        }

        $type = match ($details['type']) {
            OPENSSL_KEYTYPE_RSA => 'rsa',
            OPENSSL_KEYTYPE_EC => 'ec',
            OPENSSL_KEYTYPE_DSA => 'dsa',
            default => throw new RuntimeException('Unknown key type: ' . $details['type']),
        };

        return [
            'type' => $type,
            'role' => $role,
            'key' => $key,
        ];
    }
}
