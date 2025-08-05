<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Cek;

use Exception;
use LogicException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidCekLength;
use Phithi92\JsonWebToken\Interfaces\CekHandlerInterface;
use Phithi92\JsonWebToken\Token\EncryptedJwtBundle;

final class DefaultCekHandler implements CekHandlerInterface
{
    public function initializeCek(EncryptedJwtBundle $bundle, array $config): void
    {
        $byteLength = $this->getByteLength($config);

        $cek = $this->generateRandomCek($byteLength);

        $bundle->getEncryption()->setCek($cek);
    }

    public function validateCek(EncryptedJwtBundle $bundle, array $config): void
    {
        $cek = $bundle->getEncryption()->getCek();

        $this->validateCekLength($cek, $config);
    }

    /**
     * @param array<string, int|string|bool> $config Configuration array with 'length' key in bits
     */
    private function isStrictLengthEnabled(array $config): bool
    {
        return isset($config['strict_length']) && (bool) $config['strict_length'] === true;
    }

    /**
     * @param array<string, int|string> $config
     *
     * @throws InvalidCekLength
     */
    private function validateCekLength(string $cek, array $config): void
    {
        $expectedBytes = $this->getByteLength($config);
        $strict = $this->isStrictLengthEnabled($config);
        $cekLength = strlen($cek);

        if ($strict) {
            if ($cekLength !== $expectedBytes) {
                throw new InvalidCekLength($cekLength, $expectedBytes);
            }
        } else {
            if ($cekLength < $expectedBytes) {
                throw new InvalidCekLength($cekLength, $expectedBytes);
            }
        }
    }

    /**
     * Returns the CEK bytes length from configuration after validation.
     *
     * Ensures that the value is a positive integer and divisible by 8 (i.e., convertible to bytes).
     *
     * Assumes that the configured bit length is always at least 16 bits,
     * so the resulting byte length is guaranteed to be ≥ 2.
     *
     * @param array<string, int|string> $config Configuration array with 'length' key in bits
     *
     * @return int The CEK bytes length
     *
     * @phpstan-return int<2, max>
     *
     * @throws LogicException If the bit length is missing, non-positive, or not divisible by 8
     */
    private function getByteLength(array $config): int
    {
        $bitLength = (int) $config['length'];
        if ($bitLength < 16 || $bitLength % 8 !== 0) {
            throw new LogicException('Invalid CEK bit length: must be >= 16 and divisible by 8');
        }
        return $bitLength >> 3;
    }

    /**
     * Generates a cryptographically secure random CEK (Content Encryption Key).
     *
     * Uses PHP's random_bytes() to generate a binary string of the given byte length.
     *
     * @param int $byteLength The length of the CEK in bytes (must be ≥ 1)
     *
     * @phpstan-param int<1, max> $byteLength
     *
     * @return string Binary-encoded CEK
     *
     * @throws Exception If random_bytes() fails (e.g. due to system entropy issues)
     */
    private function generateRandomCek(int $byteLength): string
    {
        return random_bytes($byteLength);
    }
}
