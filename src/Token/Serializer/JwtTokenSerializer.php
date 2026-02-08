<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Serializer;

use Phithi92\JsonWebToken\Exceptions\Token\MalformedTokenException;
use Phithi92\JsonWebToken\Token\Codec\JwtHeaderJsonCodec;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadJsonCodec;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtTokenKind;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use ValueError;

final class JwtTokenSerializer
{
    private const SEGMENT_SEPERATOR = '.';

    public static function serialize(JwtBundle $bundle): string
    {
        $type = (string) $bundle->getHeader()->getType();

        try {
            $kind = JwtTokenKind::from($type);
        } catch (ValueError) {
            throw new MalformedTokenException('unsupported "typ" header value.');
        }

        return $kind->isSignatureToken()
            ? self::serializeSignatureToken($bundle)
            : self::serializeEncodedToken($bundle);
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
        $out = '';
        $first = true;

        foreach ($array as $v) {
            if (! $first) {
                $out .= self::SEGMENT_SEPERATOR;
            }

            $out .= Base64UrlEncoder::encode($v ?? '');
            $first = false;
        }

        return $out;
    }
}
