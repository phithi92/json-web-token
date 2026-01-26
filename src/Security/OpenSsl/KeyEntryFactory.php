<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Security\OpenSsl;

use OpenSSLAsymmetricKey;
use Phithi92\JsonWebToken\Security\KeyEntry;
use Phithi92\JsonWebToken\Security\KeyRole;
use Phithi92\JsonWebToken\Security\KeyType;
use RuntimeException;
use SensitiveParameter;

use function is_int;
use function is_string;
use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function trim;

final class KeyEntryFactory
{
    public function build(
        #[SensitiveParameter]
        string|OpenSSLAsymmetricKey $key,
        KeyRole $role,
    ): KeyEntry {
        $resolvedKey = $this->resolveKey($key, $role);
        [$type, $bits] = $this->resolveKeyDetails($resolvedKey);

        $pem = $key instanceof OpenSSLAsymmetricKey
            ? $this->resolvePemFromKey($resolvedKey, $role)
            : $key;

        return new KeyEntry(
            key: $resolvedKey,
            role: $role,
            type: $type,
            pem: $pem,
            bits: $bits,
        );
    }

    private function resolvePemFromKey(OpenSSLAsymmetricKey $key, KeyRole $role): string
    {
        return match ($role) {
            KeyRole::Private => $this->exportPrivatePem($key),
            KeyRole::Public  => $this->exportPublicPem($key),
        };
    }

    private function exportPrivatePem(OpenSSLAsymmetricKey $key): string
    {
        $pem = null;

        if (!openssl_pkey_export($key, $pem) || !is_string($pem) || trim($pem) === '') {
            throw new RuntimeException('Unable to export private key PEM from OpenSSL key.');
        }

        return trim($pem);
    }

    private function exportPublicPem(OpenSSLAsymmetricKey $key): string
    {
        $details = openssl_pkey_get_details($key);

        if ($details === false || !isset($details['key']) || !is_string($details['key']) || trim($details['key']) === '') {
            throw new RuntimeException('Unable to export public key PEM from OpenSSL key.');
        }

        return trim($details['key']);
    }

    private function resolveKey(
        #[SensitiveParameter]
        string|OpenSSLAsymmetricKey $pemOrKey,
        KeyRole $role,
    ): OpenSSLAsymmetricKey {
        if ($pemOrKey instanceof OpenSSLAsymmetricKey) {
            return $pemOrKey;
        }

        return match ($role) {
            KeyRole::Private => $this->ensureKey(openssl_pkey_get_private($pemOrKey)),
            KeyRole::Public  => $this->ensureKey(openssl_pkey_get_public($pemOrKey)),
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
     * @return array{KeyType, int} [type, bits]
     */
    private function resolveKeyDetails(
        #[SensitiveParameter]
        OpenSSLAsymmetricKey $key,
    ): array {
        $details = openssl_pkey_get_details($key);
        if ($details === false) {
            throw new RuntimeException('Could not determine key details.');
        }

        $type = $details['type'] ?? null;
        $bits = $details['bits'] ?? null;

        if (!is_int($type) || !is_int($bits)) {
            throw new RuntimeException('Could not determine key details.');
        }

        return [KeyType::fromOpenSsl($type), $bits];
    }
}
