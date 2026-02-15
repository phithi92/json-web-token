<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\KeyManagement;

use InvalidArgumentException;

interface CekHandlerInterface
{
    /**
     * Initializes a Content Encryption Key (CEK) for the given algorithm.
     *
     * @param string $algorithm The key encryption algorithm
     * @param int<16, max> $length The desired bit length (must be divisible by 8)
     *
     * @return CekHandlerResult|null Returns null for direct encryption (dir)
     *
     * @throws InvalidArgumentException If bit length constraints are violated
     */
    public function initializeCek(string $algorithm, int $length): ?CekHandlerResult;
}
