<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\KeyManagement;

use LogicException;

use function random_bytes;

final class CekHandler implements CekHandlerInterface
{
    public function initializeCek(string $algorithm, int $bitLength): ?CekHandlerResult
    {
        if ($algorithm === 'dir') {
            return null;
        }

        if ($bitLength < 16 || $bitLength % 8 !== 0) {
            throw new LogicException('Invalid CEK bit length: must be >= 16 and divisible by 8');
        }

        $byteLength = intdiv($bitLength, 8);

        // Non-dir: generate random CEK of exact required size
        $cek = random_bytes($byteLength);

        return new CekHandlerResult($cek);
    }
}
