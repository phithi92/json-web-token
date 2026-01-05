<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Codec;

use Phithi92\JsonWebToken\Exceptions\Token\MalformedTokenException;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\Parser\JwtTokenParser;
use Phithi92\JsonWebToken\Token\Serializer\JwtTokenSerializer;

final class JwtBundleCodec
{
    /**
     * @param string|array<int,string> $token
     *
     * @throws MalformedTokenException
     */
    public static function parse(string|array $token): JwtBundle
    {
        return JwtTokenParser::parse($token);
    }

    /**
     * @throws MalformedTokenException
     */
    public static function serialize(JwtBundle $bundle): string
    {
        return JwtTokenSerializer::serialize($bundle);
    }
}
