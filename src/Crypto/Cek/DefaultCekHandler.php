<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Cek;

use LogicException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidCekLength;
use Phithi92\JsonWebToken\Interfaces\CekHandlerInterface;
use Phithi92\JsonWebToken\Token\JwtBundle;

use function random_bytes;
use function strlen;

final class DefaultCekHandler implements CekHandlerInterface
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
     *
     * @param JwtBundle $bundle
     * @param array $config
     * @return void
     *
     * @throws InvalidCekLength
     * @throws MissingTokenPart
     */
    public function validateCek(JwtBundle $bundle, array $config): void
    {
        if ($bundle->getHeader()->getAlgorithm() === 'dir') {
            return;
        }

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

    private function generateRandomCek(array $config): string
    {
        $byteLength = $this->getByteLength($config);

        return random_bytes($byteLength);
    }
}
