<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Encryption;

use LogicException;
use Phithi92\JsonWebToken\Exceptions\Crypto\DecryptionException;
use Phithi92\JsonWebToken\Exceptions\Crypto\EncryptionException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidKidFormatException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Utilities\OpenSslErrorHelper;

use function in_array;
use function openssl_private_decrypt;
use function openssl_public_encrypt;
use function strlen;

/**
 * Handles RSA-specific key operations for encrypted JWTs.
 */
class RsaKeyService extends KeyCryptoService
{
    /**
     * @param array<string,string|int> $config
     *
     * @throws InvalidKidFormatException
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
     * @param array<string, int|string> $config
     *
     * @throws InvalidTokenException
     * @throws LogicException
     * @throws DecryptionException
     */
    protected function unwrap(string $wrappedKey, string $kid, array $config): string
    {
        $padding = (int) $config['padding'];

        $keyDetails = $this->manager->getKeyMetadata($kid, 'private');

        $this->assertValidPadding($padding);

        if (strlen($wrappedKey) !== $this->getKeyByteLength($keyDetails['bits'])) {
            throw new InvalidTokenException('wrong size of encrypted cek');
        }

        // Decrypt data with RSA private key
        $cek = '';
        if (! openssl_private_decrypt($wrappedKey, $cek, $keyDetails['key'], $padding)) {
            $message = OpenSslErrorHelper::getFormattedErrorMessage('Unwrap CEK Failed: ');
            throw new DecryptionException($message);
        }

        /** @var string $cek */
        return $cek;
    }

    /**
     * @param array<string, int|string> $config
     *
     * @throws LogicException
     * @throws EncryptionException
     * @throws InvalidTokenException
     */
    protected function wrap(string $cek, string $kid, array $config): string
    {
        $padding = (int) $config['padding'];

        $keyDetails = $this->manager->getKeyMetadata($kid, 'public');

        $this->assertValidPadding($padding);

        $wrappedKey = '';
        // Decrypt data with RSA private key
        if (! openssl_public_encrypt($cek, $wrappedKey, $keyDetails['key'], $padding)) {
            $message = OpenSslErrorHelper::getFormattedErrorMessage('Wrap CEK Failed: ');
            throw new EncryptionException($message);
        }

        /** @var string $wrappedKey */
        if (strlen($wrappedKey) !== $this->getKeyByteLength($keyDetails['bits'])) {
            throw new InvalidTokenException('wrong size of encrypted cek');
        }

        return $wrappedKey;
    }

    /**
     * @throws LogicException
     */
    protected function assertValidPadding(int $padding): void
    {
        $validPaddings = [
            OPENSSL_PKCS1_PADDING,
            OPENSSL_PKCS1_OAEP_PADDING,
        ];

        if (! in_array($padding, $validPaddings, true)) {
            throw new LogicException('Invalid RSA padding specified.');
        }
    }

    protected function getKeyByteLength(int $bits): int
    {
        return $bits >> 3;
    }
}
