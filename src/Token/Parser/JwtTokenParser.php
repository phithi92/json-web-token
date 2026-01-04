<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Parser;

use Phithi92\JsonWebToken\Exceptions\Base64\InvalidBase64UrlFormatException;
use Phithi92\JsonWebToken\Exceptions\Token\MalformedTokenException;
use Phithi92\JsonWebToken\Token\Codec\JwtHeaderJsonCodec;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadJsonCodec;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtEncryptionData;
use Phithi92\JsonWebToken\Token\JwtHeader;
use Phithi92\JsonWebToken\Token\JwtSignature;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;

use function array_map;
use function count;
use function explode;
use function implode;
use function is_null;
use function is_string;

final class JwtTokenParser
{
    private const JWS_PART_COUNT = 3;
    private const JWS_TYPE = 'JWS';

    private const JWE_PART_COUNT = 5;
    private const JWE_TYPE = 'JWE';

    /**
     * @param string|array<int,string> $token
     *
     * @return JwtBundle configured bundle
     *
     * @throws MalformedTokenException
     */
    public static function parse(string|array $token): JwtBundle
    {
        $tokenArray = self::normalizeTokenInput($token);

        $header = self::buildHeaderFromTokenArray($tokenArray);

        $bundle = new JwtBundle($header);

        if (! is_null($header->getType())) {
            return self::parseByType($bundle, $tokenArray);
        }

        return self::parseByStructure($bundle, $tokenArray);
    }

    /**
     * @return string Serialized token
     *
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
     * @param string|array<int,string> $token
     *
     * @return array<int,string> normalized token array
     *
     * @throws MalformedTokenException
     */
    private static function normalizeTokenInput(string|array $token): array
    {
        // The limit of 6 is intentionally chosen so we can detect
        // if a token contains more dots than expected.
        // Any additional parts will be grouped into the last element.
        $tokenArray = is_string($token) ? explode('.', $token, 6) : $token;
        if (! isset($tokenArray[0])) {
            throw new MalformedTokenException('Token is malformed or incomplete');
        }

        return $tokenArray;
    }

    /**
     * @param array<int,string> $tokenArray
     */
    private static function buildHeaderFromTokenArray(array $tokenArray): JwtHeader
    {
        $headerB64 = $tokenArray[0];

        $headerJson = self::decodeBase64Url($headerB64);

        return JwtHeaderJsonCodec::decodeStatic($headerJson);
    }

    private static function decodeBase64Url(string $base64): string
    {
        try {
            return Base64UrlEncoder::decode($base64);
        } catch (InvalidBase64UrlFormatException) {
            throw new MalformedTokenException('Cannot decode: invalid Base64Url content.');
        }
    }

    /**
     * @param array<int,string> $tokenArray
     */
    private static function parseByType(JwtBundle $bundle, array $tokenArray): JwtBundle
    {
        return match ($bundle->getHeader()->getType()) {
            self::JWS_TYPE => self::parseSignatureToken($bundle, $tokenArray),
            self::JWE_TYPE => self::parseEncodedToken($bundle, $tokenArray),
            default => throw new MalformedTokenException('Invalid or unsupported token type'),
        };
    }

    /**
     * @param array<int,string> $tokenArray
     */
    private static function parseByStructure(JwtBundle $bundle, array $tokenArray): JwtBundle
    {
        return match (count($tokenArray)) {
            self::JWS_PART_COUNT => self::parseSignatureToken($bundle, $tokenArray),
            self::JWE_PART_COUNT => self::parseEncodedToken($bundle, $tokenArray),
            default => throw new MalformedTokenException('Invalid or unsupported token type'),
        };
    }

    /**
     * @param array<int,string> $tokenArray
     *
     * @throws MalformedTokenException
     */
    private static function parseEncodedToken(JwtBundle $bundle, array $tokenArray): JwtBundle
    {
        if (count($tokenArray) !== self::JWE_PART_COUNT) {
            throw new MalformedTokenException('Invalid JWE token structure.');
        }

        $encryptionData = new JwtEncryptionData(
            aad: $tokenArray[0],
            iv: self::decodeBase64Url($tokenArray[2]),
            authTag: self::decodeBase64Url($tokenArray[4])
        );

        if ($bundle->getHeader()->getEnc() !== null && $bundle->getHeader()->getAlgorithm() !== 'dir') {
            $encryptionData = $encryptionData->withEncryptedKey(self::decodeBase64Url($tokenArray[1]));
        }

        $bundle->setEncryption($encryptionData);

        $encryptedPayload = self::decodeBase64Url($tokenArray[3]);
        $bundle->getPayload()->setEncryptedPayload($encryptedPayload);

        return $bundle;
    }

    /**
     * @param array<int,string> $tokenArray
     *
     * @throws MalformedTokenException
     */
    private static function parseSignatureToken(JwtBundle $bundle, array $tokenArray): JwtBundle
    {
        if (count($tokenArray) !== self::JWS_PART_COUNT) {
            throw new MalformedTokenException('Invalid JWS token structure.');
        }

        $bundle->setEncryption(new JwtEncryptionData(aad: $tokenArray[0] . '.' . $tokenArray[1]));

        $signature = self::decodeBase64Url($tokenArray[2]);
        $bundle->setSignature(new JwtSignature($signature));

        $payloadJson = self::decodeBase64Url($tokenArray[1]);
        JwtPayloadJsonCodec::decodeStaticInto($payloadJson, $bundle->getPayload());

        return $bundle;
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
        /** @param array<string> $tokenArray */
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
