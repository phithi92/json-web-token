<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Key;

use Exception;
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

        [$padding, $hash] = $this->extractPaddingAndHash($config);


        // Decrypt CEK with RSA private key
        $cek = $this->unwrap($wrappedKey, $kid, $padding, $hash);

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

        $publicKey = $this->buildPhpseclibPublicKey(
            pem: $key->pem(),
            config: $config
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
     *
     * @param string $wrappedKey
     * @param string $kid
     * @param int $padding
     *
     * @return string
     *
     * @throws DecryptionException
     */
    protected function unwrap(string $wrappedKey, string $kid, int $padding, ?string $hash = null): string
    {
        $keyDetails = $this->manager->getKeyMetadata($kid, KeyRole::Private);

        $privateKey = $this->buildPhpseclibPrivateKey(
            pem: $keyDetails->pem(),
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

    /**
     * @param array<string, string|int> $config
     */
    private function buildPhpseclibPublicKey(string $pem, array $config): RSAPublicKey
    {
        [$padding, $hash] = $this->extractPaddingAndHash($config);

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
