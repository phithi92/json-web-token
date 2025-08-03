<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Interfaces;

use Phithi92\JsonWebToken\Token\EncryptedJwtBundle;

/**
 * Interface ContentCryptoInterface
 *
 * Defines content-level encryption and decryption for JWT payloads,
 * as specified by the "enc" parameter in JWE.
 */
interface PayloadHandlerInterface
{
    /**
     * Encrypts the JWT payload using the configured content encryption algorithm.
     *
     * @param EncryptedJwtBundle $bundle The bundle containing the plaintext payload and encryption metadata.
     * @param array<string, array<string, string|class-string<object>>|string> $config
     *          Configuration for the encryption algorithm and key usage.
     */
    public function encryptPayload(EncryptedJwtBundle $bundle, array $config): void;

    /**
     * Decrypts the JWT payload using the configured content encryption algorithm.
     *
     * @param EncryptedJwtBundle $bundle The bundle containing the encrypted payload and decryption metadata.
     * @param array<string, array<string, string|class-string<object>>|string> $config
     *          Configuration for the decryption algorithm and key usage.
     */
    public function decryptPayload(EncryptedJwtBundle $bundle, array $config): void;
}
