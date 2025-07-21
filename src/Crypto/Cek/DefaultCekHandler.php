<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Cek;

use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidCekLength;
use Phithi92\JsonWebToken\Interfaces\CekHandlerInterface;

class DefaultCekHandler implements CekHandlerInterface
{
    public function initializeCek(EncryptedJwtBundle $jwtToken, array $config): void
    {
        $bitLength = (int) $config['length'];
        if ($bitLength < 8) {
            throw new \InvalidArgumentException('CEK length must be >= 8 bits.');
        }

        // Ensure at least 1 byte; random_bytes(0) throws and a 0-byte CEK is invalid.
        $byteLength = max(1, intdiv($bitLength, 8));

        $cek = random_bytes($byteLength);

        $jwtToken->getEncryption()->setCek($cek);
    }

    public function validateCek(EncryptedJwtBundle $jwtToken, array $config): void
    {
        $cek = $jwtToken->getEncryption()->getCek();
        $cekLength = strlen($cek);
        $expectedLength = (int) $config['length'];
        // bits
        $expectedBytes = intdiv($expectedLength, 8);
        // convert to bytes
        if ($cekLength < $expectedBytes) {
            throw new InvalidCekLength($cekLength, $expectedBytes);
        }
    }
}
