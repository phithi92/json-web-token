<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Encryption;

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
class RsaOaepKeyService extends RsaKeyService
{
    /**
     * Loads and validates an RSA public or private key from a PEM string.
     *
     * @param string $pem PEM-encoded key content
     * @param 'public'|'private' $expectedType
     *
     * @throws RuntimeException if the key type does not match
     */
    public function loadRsaKey(string $pem, string $expectedType): RSAPublicKey|RSAPrivateKey
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
     * @param array<string, string|int> $config
     *
     * @throws EncryptionException
     */
    protected function wrap(string $cek, string $kid, array $config): string
    {
        $keyDetails = $this->manager->getKeyMetadata($kid, 'public');

        $loadedKey = $this->loadRsaKey($keyDetails['pem'], 'public');

        /** @var RSAPublicKey $publicKey */
        $publicKey = $loadedKey->withPadding(RSA::ENCRYPTION_OAEP);

        if (! empty($config['hash'])) {
            $hash = (string) $config['hash'];

            /** @var RSAPublicKey $publicKey */
            $publicKey = $publicKey->withHash($hash);

            /** @var RSAPublicKey $publicKey */
            $publicKey = $publicKey->withMGFHash($hash);
        }

        $wrappedKey = $publicKey->encrypt($cek);

        if (! is_string($wrappedKey) || $wrappedKey === '') {
            throw new EncryptionException('RSA-OAEP wrap failed – empty result.');
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

        if (strlen($wrappedKey) !== ($keyDetails['bits'] >> 3)) {
            throw new InvalidTokenException('Wrong size of encrypted CEK.');
        }

        $loadedKey = $this->loadRsaKey($keyDetails['pem'], 'private');

        /** @var RSAPrivateKey $privateKey */
        $privateKey = $loadedKey->withPadding(RSA::ENCRYPTION_OAEP);

        if (! empty($config['hash'])) {
            $hash = (string) $config['hash'];

            /** @var RSAPrivateKey $privateKey */
            $privateKey = $privateKey->withHash($hash);

            /** @var RSAPrivateKey $privateKey */
            $privateKey = $privateKey->withMGFHash($hash);
        }

        $cek = $privateKey->decrypt($wrappedKey);

        if (! is_string($cek) || $cek === '') {
            throw new DecryptionException('RSA-OAEP unwrap failed – empty CEK.');
        }

        return $cek;
    }
}
