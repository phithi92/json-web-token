<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\KeyManagement;

use LogicException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidCekLength;
use Phithi92\JsonWebToken\Exceptions\Token\MissingTokenPart;
use Phithi92\JsonWebToken\Token\JwtBundle;

use function random_bytes;

final class CekHandler implements CekHandlerInterface
{
    public function initializeCek(JwtBundle $bundle, array $config): void
    {
        if ($bundle->getHeader()->getAlgorithm() === 'dir') {
            return;
        }

        // Non-dir: generate random CEK of exact required size
        $cek = $this->generateRandomCek($config);

        $bundle->setEncryption($bundle->getEncryption()->withCek($cek));
    }

    /**
     * @param array<string, int|string> $config
     *
     * @throws InvalidCekLength
     * @throws MissingTokenPart
     */
    public function validateCek(JwtBundle $bundle, array $config): void
    {
        if ($bundle->getHeader()->getAlgorithm() === 'dir') {
            return;
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
     * @param array<string, int|string> $config
     */
    private function generateRandomCek(array $config): string
    {
        $byteLength = $this->getByteLength($config);

        return random_bytes($byteLength);
    }
}
