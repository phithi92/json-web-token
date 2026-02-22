<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\ContentEncryption;

use Phithi92\JsonWebToken\Crypto\OpenSsl\OpenSslErrorHelper;
use Phithi92\JsonWebToken\Exceptions\Crypto\EncryptionException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;

use function is_string;
use function openssl_decrypt;
use function openssl_encrypt;
use function sprintf;

/**
 * AES-GCM implementation for JWE content encryption (RFC 7516 §5.3).
 *
 * This service performs authenticated encryption and decryption
 * of JWT payloads using AES in Galois/Counter Mode (GCM), as specified
 * in the JSON Web Encryption (JWE) standard.
 */
final class AesGcmHandler implements ContentEncryptionHandlerInterface
{
    private const OPENSSL_OPTIONS = OPENSSL_RAW_DATA;

    private const AUTH_TAG_LENGTH = 16;

    private OpenSslErrorHelper $errorHelper;

    public function __construct()
    {
        $this->errorHelper = new OpenSslErrorHelper();
    }

    /**
     * @throws InvalidTokenException
     */
    public function decryptPayload(
        string $encryptedData,
        string $encryptionKey,
        int $cipherKeyLength,
        string $initializationVector,
        string $authTag,
        string $additionalAuthenticatedData
    ): DecryptionHandlerResult {
        $algorithm = $this->getAesGcmCipherAlgorithm($cipherKeyLength);

        $unsealedPayload = openssl_decrypt(
            data: $encryptedData,
            cipher_algo: $algorithm,
            passphrase: $encryptionKey,
            options: self::OPENSSL_OPTIONS,
            iv: $initializationVector,
            tag: $authTag,
            aad: $additionalAuthenticatedData
        );

        if ($unsealedPayload === false) {
            $message = $this->errorHelper->getFormattedErrorMessage('Decrypt Payload Failed: ');
            throw new InvalidTokenException($message);
        }

        return new DecryptionHandlerResult($unsealedPayload);
    }

    /**
     * @throws EncryptionException
     */
    public function encryptPayload(
        string $data,
        string $encryptionKey,
        int $cipherKeyLength,
        string $initializationVector,
        string $additionalAuthenticatedData
    ): EncryptionHandlerResult {
        $authTag = '';
        $algorithm = $this->getAesGcmCipherAlgorithm($cipherKeyLength);

        $sealedPayload = openssl_encrypt(
            data: $data,
            cipher_algo: $algorithm,
            passphrase: $encryptionKey,
            options: self::OPENSSL_OPTIONS,
            iv: $initializationVector,
            tag: $authTag,
            aad: $additionalAuthenticatedData,
            tag_length: self::AUTH_TAG_LENGTH
        );

        if ($sealedPayload === false) {
            $message = $this->errorHelper->getFormattedErrorMessage('Encrypt Payload Failed: ');
            throw new EncryptionException($message);
        }

        if (! is_string($authTag)) {
            throw new EncryptionException('Encrypt Payload Failed: auth tag was not set.');
        }

        return new EncryptionHandlerResult(
            ciphertext: $sealedPayload,
            authenticationTag: $authTag
        );
    }

    private function getAesGcmCipherAlgorithm(int $bits): string
    {
        return sprintf('aes-%s-gcm', $bits);
    }
}
