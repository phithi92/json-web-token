<?php

namespace Phithi92\JsonWebToken\Crypto\Content;

use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use Phithi92\JsonWebToken\Exceptions\Crypto\DecryptionException;
use Phithi92\JsonWebToken\Exceptions\Crypto\EncryptionException;
use Phithi92\JsonWebToken\Exceptions\Crypto\InvalidAsymmetricKeyLength;

/**
 * AES-GCM implementation for JWE content encryption (RFC 7516 §5.3).
 *
 * This service performs authenticated encryption and decryption
 * of JWT payloads using AES in Galois/Counter Mode (GCM), as specified
 * in the JSON Web Encryption (JWE) standard.
 */
class AesGcmService extends ContentCryptoService
{
    const OPENSSL_OPTIONS = OPENSSL_RAW_DATA;
    /**
     *
     * @param EncryptedJwtBundle $bundle
     * @param array $config
     * @return string
     * @throws InvalidAsymmetricKeyLength
     * @throws DecryptionException
     * @throws \Exception
     */
    public function decryptPayload(EncryptedJwtBundle $bundle, array $config): void
    {
        $bits = (int)$config['length'];
        $algorithm = sprintf("aes-%s-gcm", $bits);

        $cek            = $bundle->getEncryption()->getCek();
        $iv             = $bundle->getEncryption()->getIv();
        $authTag        = $bundle->getEncryption()->getAuthTag();
        $aad            = $bundle->getEncryption()->getAad();
        $ciphertext     = $bundle->getPayload()->getEncryptedPayload();

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
            throw new DecryptionException(openssl_error_string());
        }

        $bundle->getPayload()->fromJson($plaintext);
    }

    public function encryptPayload(EncryptedJwtBundle $bundle, array $config): void
    {
        $bits       = (int)$config['length'];
        $cek        = $bundle->getEncryption()->getCek();
        $iv         = $bundle->getEncryption()->getIv();
        $plaintext  = $bundle->getPayload()->toJson();
        $aad        = Base64UrlEncoder::encode($bundle->getHeader()->toJson());
        $authTag    = '';
        $algorithm  = sprintf("aes-%s-gcm", $bits);

        $encrypted  = openssl_encrypt(
            $plaintext,
            $algorithm,
            $cek,
            self::OPENSSL_OPTIONS,
            $iv,
            $authTag,
            $aad
        );

        if (!$encrypted) {
            throw new EncryptionException(openssl_error_string());
        }

        $bundle->getPayload()->setEncryptedPayload($encrypted);
        $bundle->getEncryption()->setAuthTag($authTag);
    }
}
