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
    private const SEGMENT_SEPARATOR = '.';

    /**
     * @return non-empty-string the token
     */
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
     * @return non-empty-string serialized and encoded token
     */
    private static function serializeEncodedToken(JwtBundle $bundle): string
    {
        $encryptedKey = $bundle->getHeader()->getAlgorithm() === 'dir'
            ? ''
            : $bundle->getEncryption()->getEncryptedKey();

        return Base64UrlEncoder::encode(JwtHeaderJsonCodec::encodeStatic($bundle->getHeader()))
            . self::SEGMENT_SEPARATOR
            . Base64UrlEncoder::encode($encryptedKey)
            . self::SEGMENT_SEPARATOR
            . Base64UrlEncoder::encode($bundle->getEncryption()->getIv())
            . self::SEGMENT_SEPARATOR
            . Base64UrlEncoder::encode($bundle->getPayload()->getEncryptedPayload())
            . self::SEGMENT_SEPARATOR
            . Base64UrlEncoder::encode($bundle->getEncryption()->getAuthTag());
    }

    /**
     * @return non-empty-string
     */
    private static function serializeSignatureToken(JwtBundle $bundle): string
    {
        return Base64UrlEncoder::encode(JwtHeaderJsonCodec::encodeStatic($bundle->getHeader()))
            . self::SEGMENT_SEPARATOR
            . Base64UrlEncoder::encode(JwtPayloadJsonCodec::encodeStatic($bundle->getPayload()))
            . self::SEGMENT_SEPARATOR
            . Base64UrlEncoder::encode((string) $bundle->getSignature());
    }
}
