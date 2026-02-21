<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use InvalidArgumentException;

use function sprintf;
use function strtolower;

enum SignatureHashAlgorithm: string
{
    case Sha256 = 'sha256';
    case Sha384 = 'sha384';
    case Sha512 = 'sha512';

    public static function fromName(string $algorithm): self
    {
        return match (strtolower($algorithm)) {
            self::Sha256->value => self::Sha256,
            self::Sha384->value => self::Sha384,
            self::Sha512->value => self::Sha512,
            default => throw new InvalidArgumentException(sprintf('Unsupported hash algorithm: %s', $algorithm)),
        };
    }

    public function hmacMinKeyLength(): int
    {
        return match ($this) {
            self::Sha256 => 32,
            self::Sha384 => 48,
            self::Sha512 => 64,
        };
    }

    public function rsaMinKeyBits(): int
    {
        return match ($this) {
            self::Sha256 => 2048,
            self::Sha384 => 3072,
            self::Sha512 => 4096,
        };
    }

    public function ecCurveName(): string
    {
        return match ($this) {
            self::Sha256 => 'prime256v1',
            self::Sha384 => 'secp384r1',
            self::Sha512 => 'secp521r1',
        };
    }
}
