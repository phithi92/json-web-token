<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token;

enum JwtTokenKind: string
{
    case JWS = 'JWS';
    case JWE = 'JWE';
    case JWT = 'JWT'; // oft synonym zu JWS

    public function partCount(): int
    {
        return match ($this) {
            self::JWS, self::JWT => 3,
            self::JWE => 5,
        };
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
