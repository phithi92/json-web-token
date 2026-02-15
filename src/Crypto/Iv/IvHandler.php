<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Iv;

use InvalidArgumentException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;

use function intdiv;
use function random_bytes;
use function strlen;

/**
 * Responsible for generating and validating the Initialization Vector (IV)
 * used in content encryption (e.g. AES-GCM).
 */
final class IvHandler implements IvHandlerInterface
{
    private const BITS_PER_BYTE = 8;

    /**
     * Generate a cryptographically secure IV and store it in the bundle.
     *
     * @param int $ivLengthBits
     *
     * @return IvHandlerResult
     */
    public function initializeIv(int $ivLengthBits): IvHandlerResult
    {
        $ivLengthBytes = self::assertValidByteLength($ivLengthBits);

        // Secure random IV
        $iv = random_bytes($ivLengthBytes);

        return new IvHandlerResult(initializationVector: $iv);
    }

    /**
     * Validates the Initialization Vector (IV) in the bundle.
     *
     * @param string $iv
     * @param int $expectedLengthInBits
     *
     * @return void
     *
     * @throws InvalidTokenException If the IV is missing or has an unexpected length
     */
    public function validateIv(string $iv, int $expectedLengthInBits): void
    {

        $expectedLengthInBytes = self::assertValidByteLength($expectedLengthInBits);

        // Actual IV length
        $actual = strlen($iv);

        // Validate IV length
        if ($actual !== $expectedLengthInBytes) {
            throw new InvalidTokenException(
                sprintf(
                    'Initialization vector length mismatch (got %d bytes, expected %d)',
                    $actual,
                    $expectedLengthInBytes
                )
            );
        }
    }

    /**
     * @return positive-int
     */
    private static function assertValidByteLength(int $bits): int
    {
        // bits -> bytes
        $bytes = intdiv($bits, self::BITS_PER_BYTE);

        if ($bytes < 1) {
            throw new InvalidArgumentException(
                'IV length must be >= 8 bits (>= 1 byte). Got: ' . $bits . ' bits.'
            );
        }

        return $bytes;
    }
}
