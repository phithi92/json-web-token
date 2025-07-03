<?php

namespace Phithi92\JsonWebToken\Crypto\Encryption;

use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Exceptions\Crypto\InvalidInitializeVectorException;
use Phithi92\JsonWebToken\Interfaces\InitializationVectorManagerInterface;
use Phithi92\JsonWebToken\Exceptions\Crypto\InvalidInitializationVectorConfigException;

/**
 * Responsible for generating and validating the Initialization Vector (IV)
 * used in content encryption (e.g. AES-GCM).
 */
final class IvService implements InitializationVectorManagerInterface
{
    /**
     * Generate a cryptographically secure IV and store it in the bundle.
     *
     * @param   EncryptedJwtBundle $bundle The JWT encryption container
     * @param   array<string, int|string> $config
     */
    public function prepareIv(EncryptedJwtBundle $bundle, array $config): void
    {
        $length         = (int)$config['length'];   // IV length in bits
        $expectedBytes  = intdiv($length, 8);

        if ($expectedBytes < 1) {
            throw new InvalidInitializationVectorConfigException($expectedBytes, 8);
        }

        $iv = random_bytes($expectedBytes); // Secure random IV
        if (strlen($iv) !== $expectedBytes) {
            throw new InvalidInitializeVectorException(strlen($iv), $expectedBytes);
        }

        $bundle->getEncryption()->setIv($iv);   // Store IV in the bundle
    }

    /**
     * Validates the Initialization Vector (IV) in the bundle.
     *
     * @param   EncryptedJwtBundle $bundle The JWT encryption container
     * @param   array<string, int|string> $config
     *
     * @throws InvalidInitializeVectorException If the IV is missing or has an unexpected length
     */
    public function validateIv(EncryptedJwtBundle $bundle, array $config): void
    {
        $expectedBits = (int)($config['length']);
        $expectedBytes = intdiv($expectedBits, 8);

        if ($expectedBytes < 1) {
            throw new InvalidInitializationVectorConfigException($expectedBytes, 8);
        }

        $iv = $bundle->getEncryption()->getIv();

        if (empty($iv)) {
            throw new InvalidInitializeVectorException(0, $expectedBytes);
        }

        if (strlen($iv) !== $expectedBytes) {
            throw new InvalidInitializeVectorException(strlen($iv), $expectedBytes);
        }
    }
}
