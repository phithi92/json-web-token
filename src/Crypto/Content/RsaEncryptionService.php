<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Content;

use Phithi92\JsonWebToken\Algorithms\Content\ContentCryptoService;
use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\DecryptionException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\EncryptionException;

class RsaEncryptionService extends ContentCryptoService
{
    public function decryptPayload(EncryptedJwtBundle $bundle, array $config): void
    {
        $encryptedKey = $bundle->getEncryption()->getEncryptedKey();
        $padding = $config['padding'];
        $privateKey = $this->manager->getPrivateKey();
        $data = '';

        // Decrypt data with RSA private key
        if (!openssl_private_decrypt($encryptedKey, $data, $privateKey, $padding)) {
            throw new DecryptionException();
        }

        // Result may be empty if decryption libary is configured incorrectly
        // or if memory allocation fails
        if (empty($data)) {
            throw new DecryptionException();
        }

        $bundle->getEncryption()->setCek($data);
    }

    public function encryptPayload(EncryptedJwtBundle $bundle, array $config): void
    {
        $data = $bundle->getEncryption()->getCek();
        $padding = $config['padding'];
        $publicKey = $this->manager->getPublicKey();
        $encrypted = '';

        // Encrypt data with RSA public key
        if (!openssl_public_encrypt($data, $encrypted, $publicKey, $padding)) {
            throw new EncryptionException();
        }

        // Result may be empty if encryption libary is configured incorrectly
        // or if memory allocation fails
        if (empty($encrypted)) {
            throw new EncryptionException();
        }

        $bundle->getEncryption()->setEncryptedKey($encrypted);
    }
}
