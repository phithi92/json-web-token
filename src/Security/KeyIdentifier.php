<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Security;

use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;

final class KeyIdentifier
{
    public static function fromPem(string $pem): string
    {
        return Base64UrlEncoder::encode(hash('sha256', $pem, true));
    }

    public static function fromSecret(string $secret): string
    {
        return Base64UrlEncoder::encode(hash('sha256', $secret, true));
    }
}
