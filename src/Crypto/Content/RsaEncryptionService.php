<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Content;

use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Exceptions\Crypto\DecryptionException;
use Phithi92\JsonWebToken\Exceptions\Crypto\EncryptionException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidSignatureException;

class RsaEncryptionService extends ContentCryptoService
{
    /**
     * @param array<string,int|string> $config
     *
     * @throws DecryptionException
     */
    public function decryptPayload(EncryptedJwtBundle $bundle, array $config): void
    {
        $kid = $bundle->getHeader()->getKid() ?? $config['name'] ?? null;
        if (! is_string($kid)) {
            throw new InvalidSignatureException('No key ID (kid) provided for signature validation.');
        }

        $encryptedData = $bundle->getPayload()->getEncryptedPayload();
        $padding = (int) $config['padding'];
        $privateKey = $this->manager->getPrivateKey($kid);

        $jsonData = '';
        if (! openssl_private_decrypt($encryptedData, $jsonData, $privateKey, $padding)) {
            throw new DecryptionException($this->getOpenSslError('decryption'));
        }
        
        $bundle->getPayload()->fromJson($jsonData);
    }

    /**
     * @param array<string,int|string> $config
     *
     * @throws EncryptionException
     */
    public function encryptPayload(EncryptedJwtBundle $bundle, array $config): void
    {
        $kid = $bundle->getHeader()->getKid() ?? $config['name'] ?? null;
        if (! is_string($kid)) {
            throw new InvalidSignatureException('No key ID (kid) provided for signature validation.');
        }

        $data = $bundle->getPayload()->toJson();
        $padding = (int) $config['padding'];
        $publicKey = $this->manager->getPublicKey($kid);
        $encrypted = '';

        if (! openssl_public_encrypt($data, $encrypted, $publicKey, $padding) || empty($encrypted)) {
            throw new EncryptionException($this->getOpenSslError('encryption'));
        }

        $bundle->getPayload()->setEncryptedPayload($encrypted);
    }

    private function getOpenSslError(string $context): string
    {
        return openssl_error_string() ?: "Unknown OpenSSL {$context} error";
    }
}
