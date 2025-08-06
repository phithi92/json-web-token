<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Content;

use Phithi92\JsonWebToken\Exceptions\Crypto\DecryptionException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Token\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Utilities\OpenSslErrorHelper;

final class RsaEncryptionService extends ContentCryptoService
{
    /**
     * @param array<string,int|string> $config
     */
    public function decryptPayload(EncryptedJwtBundle $bundle, array $config): void
    {
        $kid = $bundle->getHeader()->getKid();

        $this->decrypt($bundle, $kid, $config);
    }

    /**
     * @param array<string,int|string> $config
     */
    public function encryptPayload(EncryptedJwtBundle $bundle, array $config): void
    {
        $kid = $bundle->getHeader()->getKid();

        $this->encrypt($bundle, $kid, $config);
    }

    /**
     * @param array<string,int|string> $config
     *
     * @throws DecryptionException
     */
    public function decrypt(EncryptedJwtBundle $bundle, string $kid, array $config): void
    {
        $padding = (int) $config['padding'];
        $privateKey = $this->manager->getPrivateKey($kid);
        $encrypted = $bundle->getPayload()->getEncryptedPayload();

        $decrypted = '';
        if (! openssl_private_decrypt($encrypted, $decrypted, $privateKey, $padding)) {
            $message = OpenSslErrorHelper::getFormattedErrorMessage('Decrypt Payload Failed: ');
            throw new DecryptionException($message);
        }

        /** @var string $decrypted */
        $bundle->getPayload()->fromJson($decrypted);
    }

    /**
     * @param array<string,int|string> $config
     *
     * @throws InvalidTokenException
     */
    public function encrypt(EncryptedJwtBundle $bundle, string $kid, array $config): void
    {
        $padding = (int) $config['padding'];
        $publicKey = $this->manager->getPublicKey($kid);
        $plain = $bundle->getPayload()->toJson();

        $encrypted = '';
        if (! openssl_public_encrypt($plain, $encrypted, $publicKey, $padding)) {
            $message = OpenSslErrorHelper::getFormattedErrorMessage('Encrypt Payload Failed: ');
            throw new InvalidTokenException($message);
        }

        /** @var string $encrypted */
        $bundle->getPayload()->setEncryptedPayload($encrypted);
    }
}
