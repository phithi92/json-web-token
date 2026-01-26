<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Security;

use RuntimeException;

enum KeyType: string
{
    case RSA = 'rsa';
    case EC  = 'ec';
    case DSA = 'dsa';

    public static function fromOpenSsl(int $type): self
    {
        return match ($type) {
            OPENSSL_KEYTYPE_RSA => self::RSA,
            OPENSSL_KEYTYPE_EC  => self::EC,
            OPENSSL_KEYTYPE_DSA => self::DSA,
            default => throw new RuntimeException('Unknown key type: ' . $type),
        };
    }
}
