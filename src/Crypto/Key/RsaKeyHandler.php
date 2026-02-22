<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Key;

use Exception;
use Phithi92\JsonWebToken\Exceptions\Crypto\DecryptionException;
use Phithi92\JsonWebToken\Exceptions\Crypto\EncryptionException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Security\KeyRole;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA\PrivateKey as RSAPrivateKey;
use phpseclib3\Crypt\RSA\PublicKey as RSAPublicKey;
use RuntimeException;

use function is_string;

/**
 * Handles RSA-specific key operations for encrypted JWTs.
 */
class RsaKeyHandler implements KeyHandlerInterface
{
    private JwtKeyManager $manager;

    public function __construct(JwtKeyManager $manager)
    {
        $this->manager = $manager;
    }

    public function unwrapKey(string $kid, string $wrappedKey, int $padding, string $hash): KeyUnwrapperHandlerResult
    {
        $key = $this->manager->getKeyMetadata($kid, KeyRole::Private);

        // Decrypt CEK with RSA private key
        $cek = $this->unwrap($wrappedKey, $key->pem(), $padding, $hash);

        return new KeyUnwrapperHandlerResult(contentEncryptionKey: $cek);
    }

    public function wrapKey(string $kid, string $cek, int $padding, string $hash): KeyWrapperHandlerResult
    {
        $key = $this->manager->getKeyMetadata($kid, KeyRole::Public);

        // Encrypt CEK with RSA public key
        $wrappedKey = $this->wrap($cek, $key->pem(), $padding, $hash);

        return new KeyWrapperHandlerResult(wrappedKey: $wrappedKey);
    }

    /**
     * @throws InvalidTokenException
     * @throws EncryptionException
     */
    protected function wrap(string $cek, string $pem, int $padding, string $hash): string
    {
        $publicKey = $this->buildPhpseclibPublicKey(
            pem: $pem,
            padding: $padding,
            hash: $hash
        );

        try {
            $wrappedKey = $publicKey->encrypt($cek);
        } catch (Exception $e) {
            throw new InvalidTokenException($e->getMessage());
        }

        if (! is_string($wrappedKey) || $wrappedKey === '') {
            throw new EncryptionException('RSA encryption failed – empty result.');
        }

        return $wrappedKey;
    }

    /**
     * @throws InvalidTokenException
     * @throws DecryptionException
     */
    protected function unwrap(string $wrappedKey, string $pem, int $padding, ?string $hash = null): string
    {
        $privateKey = $this->buildPhpseclibPrivateKey(
            pem: $pem,
            padding: $padding,
            hash: $hash
        );

        try {
            $cek = $privateKey->decrypt($wrappedKey);
        } catch (Exception $e) {
            throw new InvalidTokenException($e->getMessage());
        }

        if (! is_string($cek) || $cek === '') {
            throw new DecryptionException('RSA unwrap failed – empty CEK.');
        }

        return $cek;
    }

    /**
     * Loads and validates an RSA public or private key from a PEM string.
     *
     * @param string  $pem           PEM-encoded key content
     * @param KeyRole $expectedType  Expected key role (public or private)
     *
     * @throws RuntimeException If the loaded key does not match the expected role
     *
     * @phpstan-return (
     *     $expectedType is KeyRole::Private
     *         ? RSAPrivateKey
     *         : RSAPublicKey
     * )
     */
    private function loadRsaKey(
        string $pem,
        KeyRole $expectedType
    ): RSAPublicKey|RSAPrivateKey {
        $key = PublicKeyLoader::load($pem);

        if ($expectedType->value === KeyRole::Public->value && $key instanceof RSAPublicKey) {
            return $key;
        }

        if ($expectedType->value === KeyRole::Private->value && $key instanceof RSAPrivateKey) {
            return $key;
        }

        throw new RuntimeException(
            'Expected RSA ' . $expectedType->value . ' key, got ' . $key::class
        );
    }

    private function buildPhpseclibPrivateKey(string $pem, int $padding, ?string $hash = null): RSAPrivateKey
    {
        $key = $this
            ->loadPrivateKey($pem)
            ->withPadding($padding);

        if ($hash === null) {
            return $key;
        }

        return $key
            ->withHash($hash)
            ->withMGFHash($hash);
    }

    private function buildPhpseclibPublicKey(string $pem, int $padding, string $hash): RSAPublicKey
    {
        $key = $this
            ->loadPublicKey($pem)
            ->withPadding($padding);

        if ($hash === null) {
            return $key;
        }

        return $key
            ->withHash($hash)
            ->withMGFHash($hash);
    }

    private function loadPrivateKey(string $pem): RSAPrivateKey
    {
        return $this->loadRsaKey($pem, KeyRole::Private);
    }
    private function loadPublicKey(string $pem): RSAPublicKey
    {
        return $this->loadRsaKey($pem, KeyRole::Public);
    }
}
