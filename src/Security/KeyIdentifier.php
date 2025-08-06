<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Security;

use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;

final class KeyIdentifier
{
    public static function fromPem(#[\SensitiveParameter] string $pem): string
    {
        return Base64UrlEncoder::encode(self::hashKey($pem));
    }

    public static function fromSecret(#[\SensitiveParameter] string $secret): string
    {
        return Base64UrlEncoder::encode(self::hashKey($secret));
    }

    private static function hashKey(string $pem): string
    {
        return hash('sha256', $pem, true);
    }
}
