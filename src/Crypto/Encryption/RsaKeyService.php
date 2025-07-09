<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Encryption;

use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Exceptions\Crypto\DecryptionException;
use Phithi92\JsonWebToken\Exceptions\Crypto\EncryptionException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidSignatureException;

/**
 * Handles RSA-specific key operations for encrypted JWTs.
 */
class RsaKeyService extends KeyCryptoService
{
    public function unwrapKey(EncryptedJwtBundle $bundle, array $config): void
    {
        $kid = $bundle->getHeader()->getKid() ?? $config['name'] ?? null;
        if (! is_string($kid)) {
            throw new InvalidSignatureException('No key ID (kid) provided for signature validation.');
        }

        $encryptedKey = $bundle->getEncryption()->getEncryptedKey();
        $padding = (int) $config['padding'];
        $data = '';

        $privateKey = $this->manager->getPrivateKey($kid);

        // Decrypt data with RSA private key
        if (! openssl_private_decrypt($encryptedKey, $data, $privateKey, $padding)) {
            throw new InvalidSignatureException('Token invalid. Key unwrap failed.');
        }

        // Result may be empty if decryption libary is configured incorrectly
        // or if memory allocation fails
        if (empty($data)) {
            throw new DecryptionException(openssl_error_string() ?: 'Key unwrap failed.');
        }

        $bundle->getEncryption()->setCek($data);
    }

    public function wrapKey(EncryptedJwtBundle $bundle, array $config): void
    {
        $kid = $bundle->getHeader()->getKid() ?? $config['name'] ?? null;
        if (! is_string($kid)) {
            throw new InvalidSignatureException('No key ID (kid) provided for signature validation.');
        }

        // Generate CEK (Content Encryption Key)
        $cek = $bundle->getEncryption()->getCek();
        $padding = (int) $config['padding'];
        $encrypted = '';

        $publicKey = $this->manager->getPublicKey($kid);

        // Encrypt CEK with RSA public key
        if (! openssl_public_encrypt($cek, $encrypted, $publicKey, $padding)) {
            throw new EncryptionException(openssl_error_string() ?: 'Key unwrap failed.');
        }

        if (empty($encrypted)) {
            throw new EncryptionException(openssl_error_string() ?: 'Key unwrap failed.');
        }

        $bundle->getEncryption()->setEncryptedKey($encrypted);
    }
}
