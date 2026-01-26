<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Serializer;

use Phithi92\JsonWebToken\Token\Codec\JwtHeaderJsonCodec;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadJsonCodec;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;

final class JwsSigningInput
{
    public static function fromBundle(JwtBundle $bundle): string
    {
        return Base64UrlEncoder::encode(JwtHeaderJsonCodec::encodeStatic($bundle->getHeader()))
            . '.'
            . Base64UrlEncoder::encode(JwtPayloadJsonCodec::encodeStatic($bundle->getPayload()));
    }
}
