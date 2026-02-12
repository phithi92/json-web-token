<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\ContentEncryption;

use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;

/**
 * Interface ContentCryptoInterface.
 *
 * Defines content-level encryption and decryption for JWT payloads,
 * as specified by the "enc" parameter in JWE.
 */
interface ContentEncryptionHandlerInterface
{
    public function __construct(JwtKeyManager $manager);

    /**
     * Encrypts plaintext using AEAD (e.g., AES-GCM).
     *
     * @param string $data                         Plaintext to encrypt.
     * @param string $encryptionKey                Secret key (raw binary/base64).
     * @param int    $cipherKeyLength              Key length in bits (e.g., 256).
     * @param string $initializationVector         Unique IV (length: openssl_cipher_iv_length()).
     * @param string $additionalAuthenticatedData  AAD for integrity (unencrypted).
     *
     * @return EncryptionHandlerResult             Contains ciphertext, IV, and auth tag.
     */
    public function encryptPayload(
        string $data,
        string $encryptionKey,
        int $cipherKeyLength,
        string $initializationVector,
        string $additionalAuthenticatedData
    ): EncryptionHandlerResult;

    /**
     * Decrypts AEAD-encrypted payload (e.g., AES-GCM).
     *
     * @param string $encryptedData                Ciphertext to decrypt.
     * @param string $encryptionKey                Secret key (raw binary/base64).
     * @param int    $cipherKeyLength              Key length in bits (e.g., 256).
     * @param string $initializationVector         IV from encryption.
     * @param string $authTag                      Authentication tag (16 bytes for AES-GCM).
     * @param string $additionalAuthenticatedData  AAD from encryption.
     *
     * @return DecryptionHandlerResult             Contains decrypted plaintext.
     */
    public function decryptPayload(
        string $encryptedData,
        string $encryptionKey,
        int $cipherKeyLength,
        string $initializationVector,
        string $authTag,
        string $additionalAuthenticatedData
    ): DecryptionHandlerResult;
}
