<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\KeyManagement;

use Exception;
use InvalidArgumentException;
use RuntimeException;

use function random_bytes;

final class CekHandler implements CekHandlerInterface
{
    private const ALGORITHM_DIRECT_CEK = 'dir';

    private const MIN_BIT_LENGTH = 128; // 16 bytes minimum for security
    private const BITS_PER_BYTE = 8;

    /**
     * {@inheritDoc}
     *
     */
    public function initializeCek(string $algorithm, int $bitLength): ?CekHandlerResult
    {
        if ($algorithm === self::ALGORITHM_DIRECT_CEK) {
            return null;
        }

        if ($bitLength < self::MIN_BIT_LENGTH || $bitLength % self::BITS_PER_BYTE !== 0) {
            throw new InvalidArgumentException(sprintf(
                'Invalid CEK bit length: %d. Must be >= %d and divisible by %d',
                $bitLength,
                self::MIN_BIT_LENGTH,
                self::BITS_PER_BYTE
            ));
        }

        $byteLength = intdiv($bitLength, self::BITS_PER_BYTE);

        // Static analysis refinement: we know $byteLength >= 2 after validation
        /** @var int<2, max> $byteLength */

        try {
            $cek = random_bytes($byteLength);
        } catch (Exception $e) {
            throw new RuntimeException('Cryptographically secure random bytes generation failed', 0, $e);
        }

        return new CekHandlerResult($cek);
    }
}
