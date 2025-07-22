<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Cek;

use InvalidArgumentException;
use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidCekLength;
use Phithi92\JsonWebToken\Interfaces\CekHandlerInterface;

final class DefaultCekHandler implements CekHandlerInterface
{
    public function initializeCek(EncryptedJwtBundle $bundle, array $config): void
    {
        $bitLength = $this->getBitLength($config);

        // Ensure at least 1 byte; random_bytes(0) throws and a 0-byte CEK is invalid.
        $byteLength = max(1, intdiv($bitLength, 8));

        $cek = random_bytes($byteLength);

        $bundle->getEncryption()->setCek($cek);
    }

    public function validateCek(EncryptedJwtBundle $bundle, array $config): void
    {
        $bitLength = $this->getBitLength($config);
        $expectedBytes = intdiv($bitLength, 8);

        $cek = $bundle->getEncryption()->getCek();
        $cekLength = strlen($cek);

        if ($cekLength < $expectedBytes) {
            throw new InvalidCekLength($cekLength, $expectedBytes);
        }
    }

    /**
     * @param array<string,int|string> $config
     *
     * @throws \InvalidArgumentException
     */
    private function getBitLength(array $config): int
    {
        $bitLength = (int) $config['length'];
        if ($bitLength < 8) {
            throw new InvalidArgumentException('CEK length must be >= 8 bits.');
        }
        return $bitLength;
    }
}
