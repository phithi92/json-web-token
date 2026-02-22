<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token;

use InvalidArgumentException;
use ValueError;

use function get_debug_type;
use function is_int;
use function is_string;

enum JwtTokenKind: string
{
    case JWS = 'JWS';
    case JWE = 'JWE';
    case JWT = 'JWT';

    public function partCount(): int
    {
        return match ($this) {
            self::JWS, self::JWT => 3,
            self::JWE => 5,
        };
    }

    /**
     * @throws InvalidArgumentException
     */
    public static function fromTypeOrFail(mixed $type): self
    {
        if (! is_string($type) && ! is_int($type)) {
            throw new InvalidArgumentException(
                sprintf('Unsupported JWT type (expected string|int), got: %s', get_debug_type($type))
            );
        }

        $type = (string) $type;

        if ($type === '') {
            throw new InvalidArgumentException('Unsupported JWT type: empty string');
        }

        try {
            return self::from($type);
        } catch (ValueError $e) {
            throw new InvalidArgumentException(
                sprintf('Unsupported JWT type: %s', $type),
                previous: $e
            );
        }
    }

    public function isSignatureToken(): bool
    {
        return $this === self::JWS || $this === self::JWT;
    }

    public static function fromPartCount(int $count): ?self
    {
        return match ($count) {
            3 => self::JWS, // strukturell ist JWT/JWS identisch → JWS als Default
            5 => self::JWE,
            default => null,
        };
    }
}
