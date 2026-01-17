<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Serializer;

use Phithi92\JsonWebToken\Exceptions\Token\MalformedTokenException;
use Phithi92\JsonWebToken\Token\Codec\JwtHeaderJsonCodec;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadJsonCodec;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;

use function array_map;
use function implode;

final class JwtTokenSerializer
{
    private const JWS_TYPE = 'JWS';
    private const JWE_TYPE = 'JWE';

    /**
     * @throws MalformedTokenException
     */
    public static function serialize(JwtBundle $bundle): string
    {
        return match ($bundle->getHeader()->getType()) {
            self::JWE_TYPE => self::serializeEncodedToken($bundle),
            self::JWS_TYPE => self::serializeSignatureToken($bundle),
            default => throw new MalformedTokenException('Invalid or unsupported token type'),
        };
    }

    /**
     * @return string serialized and encoded token
     */
    private static function serializeEncodedToken(JwtBundle $bundle): string
    {
        $encryptedKey = match ($bundle->getHeader()->getAlgorithm()) {
            'dir' => '',
            default => $bundle->getEncryption()->getEncryptedKey(),
        };

        $tokenArray = [
            JwtHeaderJsonCodec::encodeStatic($bundle->getHeader()),
            $encryptedKey,
            $bundle->getEncryption()->getIv(),
            $bundle->getPayload()->getEncryptedPayload(),
            $bundle->getEncryption()->getAuthTag(),
        ];

        return self::encodeAndSerialize($tokenArray);
    }

    private static function serializeSignatureToken(JwtBundle $bundle): string
    {
        $tokenArray = [
            JwtHeaderJsonCodec::encodeStatic($bundle->getHeader()),
            JwtPayloadJsonCodec::encodeStatic($bundle->getPayload()),
            (string) $bundle->getSignature(),
        ];

        return self::encodeAndSerialize($tokenArray);
    }

    /**
     * @param array<int,string|null> $array
     */
    private static function encodeAndSerialize(array $array): string
    {
        return implode(
            '.',
            array_map(
                static fn (?string $v): string => Base64UrlEncoder::encode($v ?? ''),
                $array
            )
        );
    }
}
