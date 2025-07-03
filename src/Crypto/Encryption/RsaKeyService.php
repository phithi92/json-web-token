<?php

namespace Phithi92\JsonWebToken\Crypto\Encryption;

use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Exceptions\Crypto\DecryptionException;
use Phithi92\JsonWebToken\Exceptions\Crypto\EncryptionException;

/**
 * Handles RSA-specific key operations for encrypted JWTs.
 */
class RsaKeyService extends KeyCryptoService
{
    public function unwrapKey(EncryptedJwtBundle $bundle, array $config): void
    {
        $encryptedKey   = $bundle->getEncryption()->getEncryptedKey();
        $privateKey     = $this->manager->getPrivateKey();
        $padding        = (int)$config['padding'];
        $data           = '';

        // Decrypt data with RSA private key
        if (!openssl_private_decrypt($encryptedKey, $data, $privateKey, $padding)) {
            throw new DecryptionException(openssl_error_string() ?: 'Key unwrap failed.');
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
        // Generate CEK (Content Encryption Key)
        $cek        = $bundle->getEncryption()->getCek();
        $padding    = (int)$config['padding'];
        $publicKey  = $this->manager->getPublicKey();
        $encrypted  = '';

        // Encrypt CEK with RSA public key
        if (!openssl_public_encrypt($cek, $encrypted, $publicKey, $padding)) {
            throw new EncryptionException(openssl_error_string() ?: 'Key unwrap failed.');
        }

        if (empty($encrypted)) {
            throw new EncryptionException(openssl_error_string() ?: 'Key unwrap failed.');
        }

        $bundle->getEncryption()->setEncryptedKey($encrypted);
    }
}
