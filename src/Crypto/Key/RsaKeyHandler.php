<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Key;

use LogicException;
use Phithi92\JsonWebToken\Exceptions\Crypto\DecryptionException;
use Phithi92\JsonWebToken\Exceptions\Crypto\EncryptionException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Security\KeyRole;
use Phithi92\JsonWebToken\Token\JwtBundle;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PrivateKey as RSAPrivateKey;
use phpseclib3\Crypt\RSA\PublicKey as RSAPublicKey;
use RuntimeException;

use function is_int;
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

    /**
     * @param array<string,string|int> $config
     */
    public function unwrapKey(JwtBundle $bundle, array $config): void
    {
        $kid = $bundle->getHeader()->getKid();

        $wrappedKey = $bundle->getEncryption()->getEncryptedKey();

        // Decrypt CEK with RSA private key
        $cek = $this->unwrap($wrappedKey, $kid, $config);

        $bundle->setEncryption($bundle->getEncryption()->withCek($cek));
    }

    /**
     * @param array<string,string|int> $config
     */
    public function wrapKey(JwtBundle $bundle, array $config): void
    {
        $kid = $bundle->getHeader()->getKid();

        $cek = $bundle->getEncryption()->getCek();

        // Encrypt CEK with RSA public key
        $wrappedKey = $this->wrap($cek, $kid, $config);

        $bundle->setEncryption($bundle->getEncryption()->withEncryptedKey($wrappedKey));
    }

    /**
     * @param array<string, string|int> $config
     *
     * @throws EncryptionException
     */
    protected function wrap(string $cek, string $kid, array $config): string
    {
        $key = $this->manager->getKeyMetadata($kid, KeyRole::Public);

        $publicKey = $this->buildPublicKey(pem: $key->pem(), config: $config);

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
        $keyDetails = $this->manager->getKeyMetadata($kid, KeyRole::Private);

        $privateKey = $this->buildPrivateKey(pem: $keyDetails->pem(), config: $config);

        $cek = $privateKey->decrypt($wrappedKey);

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

    /**
     * @param array<string, string|int> $config
     */
    private function buildPrivateKey(string $pem, array $config): RSAPrivateKey
    {
        return $this->buildKey(KeyRole::Private, $pem, $config);
    }

    /**
     * @param array<string, string|int> $config
     */
    private function buildPublicKey(string $pem, array $config): RSAPublicKey
    {
        return $this->buildKey(KeyRole::Public, $pem, $config);
    }

    /**
     * @param array<string, string|int> $config
     *
     * @throws LogicException
     */
    private function buildKey(
        KeyRole $role,
        string $pem,
        array $config
    ): RSAPrivateKey|RSAPublicKey {
        $key = match ($role) {
            KeyRole::Private => $this->loadPrivateKey($pem),
            KeyRole::Public  => $this->loadPublicKey($pem),
        };

        [$padding, $hash] = $this->extractPaddingAndHash($config);

        /** @var RSAPrivateKey|RSAPublicKey $configured */
        $configured = $key->withPadding($padding);

        if ($hash === null) {
            return $configured;
        }

        /** @var RSAPrivateKey|RSAPublicKey $configured */
        $configured = $configured->withHash($hash);
        /** @var RSAPrivateKey|RSAPublicKey $configured */
        $configured = $configured->withMGFHash($hash);

        return $configured;
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
