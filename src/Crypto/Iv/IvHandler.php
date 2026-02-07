<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Iv;

use InvalidArgumentException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Token\JwtBundle;

use function is_int;
use function random_bytes;
use function strlen;

/**
 * Responsible for generating and validating the Initialization Vector (IV)
 * used in content encryption (e.g. AES-GCM).
 */
final class IvHandler implements IvHandlerInterface
{
    /**
     * Generate a cryptographically secure IV and store it in the bundle.
     */
    public function initializeIv(JwtBundle $bundle, array $config): void
    {
        $ivLength = self::resolveIvByteLengthFromConfig($config);

        // Secure random IV
        $iv = random_bytes($ivLength);

        // Store IV in the bundle
        $bundle->setEncryption($bundle->getEncryption()->withIv($iv));
    }

    /**
     * Validates the Initialization Vector (IV) in the bundle.
     *
     * @throws InvalidTokenException If the IV is missing or has an unexpected length
     */
    public function validateIv(JwtBundle $bundle, array $config): void
    {
        $expected = self::resolveIvByteLengthFromConfig($config);

        $iv = $bundle->getEncryption()->getIv();

        // Actual IV length
        $actual = strlen($iv);

        // Validate IV length
        if ($actual !== $expected) {
            throw new InvalidTokenException(
                sprintf(
                    'Initialization vector length mismatch (got %d bytes, expected %d)',
                    $actual,
                    $expected
                )
            );
        }
    }

    /**
     * @param array<string, mixed> $config
     * @return positive-int
     */
    private static function resolveIvByteLengthFromConfig(array $config): int
    {
        $bits = $config['length'] ?? null;

        if (!is_int($bits)) {
            throw new InvalidArgumentException(
                'Config key "length" must be an int (bit length).'
            );
        }

        // bits -> bytes
        $bytes = $bits >> 3;

        if ($bytes < 1) {
            throw new InvalidArgumentException(
                'IV length must be >= 8 bits (>= 1 byte). Got: ' . $bits . ' bits.'
            );
        }

        return $bytes;
    }
}
