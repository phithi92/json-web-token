<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Encryption;

use LogicException;
use Phithi92\JsonWebToken\Exceptions\Crypto\DecryptionException;
use Phithi92\JsonWebToken\Exceptions\Crypto\EncryptionException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PrivateKey as RSAPrivateKey;
use phpseclib3\Crypt\RSA\PublicKey as RSAPublicKey;
use RuntimeException;

/**
 * Handles RSA-specific key operations for encrypted JWTs.
 */
class PhpseclibRsaEncryptionService extends RsaKeyService
{
    /**
     * @param array<string, string|int> $config
     *
     * @throws EncryptionException
     */
    protected function wrap(string $cek, string $kid, array $config): string
    {
        $keyDetails = $this->manager->getKeyMetadata($kid, 'public');

        [$padding,$hash] = $this->extractPaddingAndHash($config);
        $pem = $keyDetails['pem'];

        $publicKey = $this->buildPublicKey($pem, $padding, $hash);

        $wrappedKey = $publicKey->encrypt($cek);
        if (! is_string($wrappedKey) || $wrappedKey === '') {
            throw new EncryptionException('RSA encryption failed – empty result.');
        }

        return $wrappedKey;
    }

    /**
     * @param array<string, string|int> $config
     *
     * @throws InvalidTokenException
     * @throws DecryptionException
     */
    protected function unwrap(string $wrappedKey, string $kid, array $config): string
    {
        $keyDetails = $this->manager->getKeyMetadata($kid, 'private');

        [$padding,$hash] = $this->extractPaddingAndHash($config);
        $pem = $keyDetails['pem'];

        $privateKey = $this->buildPrivateKey($pem, $padding, $hash);

        $cek = $privateKey->decrypt($wrappedKey);

        if (! $this->isValidDecryptedCek($cek)) {
            throw new DecryptionException('RSA unwrap failed – empty CEK.');
        }

        /** @var string $cek */
        return $cek;
    }
    /**
     * Loads and validates an RSA public or private key from a PEM string.
     *
     * @param string $pem PEM-encoded key content
     * @param 'public'|'private' $expectedType
     *
     * @throws RuntimeException if the key type does not match
     */
    private function loadRsaKey(string $pem, string $expectedType): RSAPublicKey|RSAPrivateKey
    {
        $key = PublicKeyLoader::load($pem);

        if ($expectedType === 'public' && $key instanceof RSAPublicKey) {
            return $key;
        }
        if ($expectedType === 'private' && $key instanceof RSAPrivateKey) {
            return $key;
        }

        throw new RuntimeException('Expected RSA public key, got ' . $key::class);
    }

    /**
     * @param array<string,string|int> $config
     *
     * @return array{int,string|null}
     */
    private function extractPaddingAndHash(array $config): array
    {
        $padding = $config['padding'] ?? RSA::ENCRYPTION_OAEP;
        $hash = $config['hash'] ?? null;

        if (! is_int($padding)) {
            throw new LogicException('Invalid padding configuration: must be int');
        }

        if (! is_string($hash) && $hash !== null) {
            throw new LogicException('Invalid hash configuration: must be string or null');
        }

        return [$padding, $hash];
    }

    private function isValidDecryptedCek(mixed $cek): bool
    {
        return is_string($cek) && $cek !== '';
    }

    private function buildPrivateKey(string $pem, int $padding, ?string $hash): RsaPrivateKey
    {
        /** @var RSAPrivateKey $key */
        return $this->buildKey('private', $pem, $padding, $hash);
    }

    private function buildPublicKey(string $pem, int $padding, ?string $hash): RsaPublicKey
    {
        /** @var RSAPublicKey $key */
        return $this->buildKey('public', $pem, $padding, $hash);
    }

    private function buildKey(string $role, string $pem, int $padding, ?string $hash): RSAPrivateKey|RSAPublicKey
    {
        if (! in_array($role, ['private','public'])) {
            throw new LogicException('No valid role for key');
        }

        /** @var RSAPrivateKey|RSAPublicKey $key */
        $key = $this->loadRsaKey($pem, $role)->withPadding($padding);

        if ($hash !== null && $role === 'private' && $key instanceof RSAPrivateKey) {
            /** @var RSAPrivateKey $key */
            $key = $key->withHash($hash);

            /** @var RSAPrivateKey $key */
            $key = $key->withMGFHash($hash);
        }

        return $key;
    }
}
