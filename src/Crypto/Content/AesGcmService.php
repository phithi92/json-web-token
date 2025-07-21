<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Content;

use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Exceptions\Crypto\EncryptionException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use Phithi92\JsonWebToken\Utilities\OpenSslErrorHelper;

/**
 * AES-GCM implementation for JWE content encryption (RFC 7516 §5.3).
 *
 * This service performs authenticated encryption and decryption
 * of JWT payloads using AES in Galois/Counter Mode (GCM), as specified
 * in the JSON Web Encryption (JWE) standard.
 */
class AesGcmService extends ContentCryptoService
{
    protected const OPENSSL_OPTIONS = OPENSSL_RAW_DATA;

    /**
     * @param array<string,int|string> $config
     *
     * @throws InvalidTokenException
     */
    public function decryptPayload(EncryptedJwtBundle $bundle, array $config): void
    {
        $bits = (int) $config['length'];
        $algorithm = sprintf('aes-%s-gcm', $bits);

        $cek = $bundle->getEncryption()->getCek();
        $iv = $bundle->getEncryption()->getIv();
        $authTag = $bundle->getEncryption()->getAuthTag();
        $aad = $bundle->getEncryption()->getAad();
        $ciphertext = $bundle->getPayload()->getEncryptedPayload();

        $plaintext = openssl_decrypt(
            $ciphertext,
            $algorithm,
            $cek,
            self::OPENSSL_OPTIONS,
            $iv,
            $authTag,
            $aad
        );

        if ($plaintext === false) {
            $message = OpenSslErrorHelper::getFormattedErrorMessage('Decrypt Payload Failed: ');
            throw new InvalidTokenException($message);
        }

        $bundle->getPayload()->fromJson($plaintext);
    }

    /**
     * @param array<string,int|string> $config
     */
    public function encryptPayload(EncryptedJwtBundle $bundle, array $config): void
    {
        $bits = (int) $config['length'];
        $algorithm = sprintf('aes-%s-gcm', $bits);

        $cek = $bundle->getEncryption()->getCek();
        $iv = $bundle->getEncryption()->getIv();
        $plaintext = $bundle->getPayload()->toJson();
        $headerJson = $bundle->getHeader()->toJson();
        $aad = Base64UrlEncoder::encode($headerJson);

        $authTag = '';
        $encrypted = openssl_encrypt(
            $plaintext,
            $algorithm,
            $cek,
            self::OPENSSL_OPTIONS,
            $iv,
            $authTag,
            $aad
        );

        if (! $encrypted) {
            $message = OpenSslErrorHelper::getFormattedErrorMessage('Encrypt Payload Failed: ');
            throw new EncryptionException($message);
        }

        $bundle->getPayload()->setEncryptedPayload($encrypted);
        /**
         * @var string $authTag
         */
        $bundle->getEncryption()->setAuthTag($authTag);
    }
}
