<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\KeyManagement;

interface CekHandlerInterface
{
    /**
     * Generates or loads the Content Encryption Key (CEK)
     */
    public function initializeCek(string $algorithm, int $length): ?CekHandlerResult;
}
