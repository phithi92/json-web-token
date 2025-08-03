<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Encryption;

use Phithi92\JsonWebToken\Exceptions\Crypto\EmptyInitializeVectorException;
use Phithi92\JsonWebToken\Exceptions\Crypto\InvalidInitializationVectorConfigException;
use Phithi92\JsonWebToken\Exceptions\Crypto\InvalidInitializationVectorException;
use Phithi92\JsonWebToken\Interfaces\IvHandlerInterface;
use Phithi92\JsonWebToken\Token\EncryptedJwtBundle;

/**
 * Responsible for generating and validating the Initialization Vector (IV)
 * used in content encryption (e.g. AES-GCM).
 */
final class IvService implements IvHandlerInterface
{
    /**
     * Generate a cryptographically secure IV and store it in the bundle.
     *
     * @param EncryptedJwtBundle        $bundle The JWT encryption container
     * @param array<string, int|string> $config
     */
    public function initializeIv(EncryptedJwtBundle $bundle, array $config): void
    {
        $bits = $this->getBitLengthFromConfig($config);
        $bytesLength = $this->normalizeAndValidateBitLength($bits);

        // Secure random IV
        $iv = $this->generateRandomIv($bytesLength);

        // Store IV in the bundle
        $bundle->getEncryption()->setIv($iv);
    }

    /**
     * Validates the Initialization Vector (IV) in the bundle.
     *
     * @param EncryptedJwtBundle        $bundle The JWT encryption container
     * @param array<string, int|string> $config
     *
     * @throws InvalidInitializationVectorException If the IV is missing or has an unexpected length
     */
    public function validateIv(EncryptedJwtBundle $bundle, array $config): void
    {
        $bits = $this->getBitLengthFromConfig($config);
        $bytesLength = $this->normalizeAndValidateBitLength($bits);

        $iv = $bundle->getEncryption()->getIv();

        // validate iv
        $this->assertValidIvLength($iv, $bytesLength);
    }

    /**
     * @param array<string, int|string> $config
     *
     * @throws InvalidInitializationVectorConfigException
     */
    private function getBitLengthFromConfig(array $config): int
    {
        if (! isset($config['length'])) {
            throw new InvalidInitializationVectorConfigException(0, 0);
        }

        $length = $config['length'];

        if (! is_int($length)) {
            throw new InvalidInitializationVectorConfigException(0, 0);
        }

        return $length;
    }

    private function assertValidIvLength(string $iv, int $expectedBytes): void
    {
        $ivBytes = strlen($iv);
        if ($ivBytes === 0) {
            throw new EmptyInitializeVectorException();
        }

        if ($ivBytes !== $expectedBytes) {
            throw new InvalidInitializationVectorException($ivBytes, $expectedBytes);
        }
    }

    /**
     * @return positive-int
     *
     * @throws InvalidInitializationVectorConfigException
     */
    private function normalizeAndValidateBitLength(int $bits): int
    {
        $expectedBytes = ($bits >> 3);
        if ($expectedBytes < 1) {
            throw new InvalidInitializationVectorConfigException(0, $expectedBytes);
        }

        return $expectedBytes;
    }

    /**
     * @param int<1, max> $byteLength
     */
    private function generateRandomIv(int $byteLength): string
    {
        $iv = random_bytes($byteLength);
        if (strlen($iv) !== $byteLength) {
            throw new InvalidInitializationVectorException(strlen($iv), $byteLength);
        }

        return $iv;
    }
}
