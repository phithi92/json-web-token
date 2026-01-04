<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Encryption;

use Phithi92\JsonWebToken\Exceptions\Crypto\EmptyInitializeVectorException;
use Phithi92\JsonWebToken\Exceptions\Crypto\InvalidInitializationVectorConfigException;
use Phithi92\JsonWebToken\Exceptions\Crypto\InvalidInitializationVectorException;
use Phithi92\JsonWebToken\Interfaces\IvHandlerInterface;
use Phithi92\JsonWebToken\Token\JwtBundle;

use function is_int;
use function random_bytes;
use function strlen;

/**
 * Responsible for generating and validating the Initialization Vector (IV)
 * used in content encryption (e.g. AES-GCM).
 */
final class IvService implements IvHandlerInterface
{
    /**
     * Generate a cryptographically secure IV and store it in the bundle.
     */
    public function initializeIv(JwtBundle $bundle, array $config): void
    {
        $byteLength = $this->normalizeAndValidateBitLength($config);

        // Secure random IV
        $iv = random_bytes($byteLength);

        $this->assertValidIvLength($iv, $byteLength);

        // Store IV in the bundle
        $bundle->setEncryption($bundle->getEncryption()->withIv($iv));
    }

    /**
     * Validates the Initialization Vector (IV) in the bundle.
     *
     * @throws InvalidInitializationVectorException If the IV is missing or has an unexpected length
     */
    public function validateIv(JwtBundle $bundle, array $config): void
    {
        $bytesLength = $this->normalizeAndValidateBitLength($config);

        $iv = $bundle->getEncryption()->getIv();

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
    private function normalizeAndValidateBitLength(array $config): int
    {
        $expectedBytes = ($this->getBitLengthFromConfig($config) >> 3);
        if ($expectedBytes < 1) {
            throw new InvalidInitializationVectorConfigException(0, $expectedBytes);
        }

        return $expectedBytes;
    }
}
