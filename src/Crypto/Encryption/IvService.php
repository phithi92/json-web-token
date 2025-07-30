<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Encryption;

use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Exceptions\Crypto\EmptyInitializeVectorException;
use Phithi92\JsonWebToken\Exceptions\Crypto\InvalidInitializationVectorConfigException;
use Phithi92\JsonWebToken\Exceptions\Crypto\InvalidInitializationVectorException;
use Phithi92\JsonWebToken\Interfaces\IvHandlerInterface;

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
        $bits = (int) $config['length'];
        $bytesLength = $this->normalizeAndValidateBitLength($bits);

        $iv = random_bytes($bytesLength);
        // Secure random IV
        if (strlen($iv) !== $bytesLength) {
            throw new InvalidInitializeVectorException(strlen($iv), $bytesLength);
        }

        $bundle->getEncryption()->setIv($iv);
        // Store IV in the bundle
    }

    /**
     * Validates the Initialization Vector (IV) in the bundle.
     *
     * @param EncryptedJwtBundle        $bundle The JWT encryption container
     * @param array<string, int|string> $config
     *
     * @throws InvalidInitializeVectorException If the IV is missing or has an unexpected length
     */
    public function validateIv(EncryptedJwtBundle $bundle, array $config): void
    {
        $bits = (int) $config['length'];
        $bytesLength = $this->normalizeAndValidateBitLength($bits);

        $iv = $bundle->getEncryption()->getIv();
        $ivLength = strlen($iv);

        $this->assertValidIvLength($ivLength, $bytesLength);
    }

    private function assertValidIvLength(int $ivBytes, int $expectedBytes): void
    {
        if ($ivBytes === 0) {
            throw new EmptyInitializeVectorException();
        }

        if ($ivBytes !== $expectedBytes) {
            throw new InvalidInitializeVectorException($ivBytes, $expectedBytes);
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
}
