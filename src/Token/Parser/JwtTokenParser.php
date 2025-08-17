<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Parser;

use Phithi92\JsonWebToken\Exceptions\Base64\InvalidBase64UrlFormatException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;
use Phithi92\JsonWebToken\Token\Codec\JwtHeaderJsonCodec;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadJsonCodec;
use Phithi92\JsonWebToken\Token\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Token\JwtHeader;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;

class JwtTokenParser
{
    private const JWS_PART_COUNT = 3;
    private const JWS_TYPE = 'JWS';

    private const JWE_PART_COUNT = 5;
    private const JWE_TYPE = 'JWE';

    /**
     * @param string|array<int,string> $token
     *
     * @return EncryptedJwtBundle configured bundle
     *
     * @throws InvalidFormatException
     */
    public static function parse(string|array $token): EncryptedJwtBundle
    {
        $tokenArray = self::normalizeTokenInput($token);

        $header = self::buildHeaderFromTokenArray($tokenArray);

        $bundle = new EncryptedJwtBundle($header);

        if (! is_null($header->getType())) {
            return self::parseByType($bundle, $tokenArray);
        }

        return self::parseByStructure($bundle, $tokenArray);
    }

    /**
     * @throws InvalidFormatException
     *
     * @return string Serialized token
     */
    public static function serialize(EncryptedJwtBundle $bundle): string
    {
        return match ($bundle->getHeader()->getType()) {
            self::JWE_TYPE => self::serializeEncodedToken($bundle),
            self::JWS_TYPE => self::serializeSignatureToken($bundle),
            default => throw new InvalidFormatException('Invalid or unsupported token type'),
        };
    }

    /**
     * @param string|array<int,string> $token
     *
     * @return array<int,string> normalized token array
     *
     * @throws InvalidFormatException
     */
    private static function normalizeTokenInput(string|array $token): array
    {
        $tokenArray = is_string($token) ? explode('.', $token) : $token;
        if (! isset($tokenArray[0])) {
            throw new InvalidFormatException('Token is malformed or incomplete');
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
            throw new InvalidFormatException('Cannot decode: invalid Base64Url content.');
        }
    }

    /**
     * @param array<int,string> $tokenArray
     */
    private static function parseByType(EncryptedJwtBundle $bundle, array $tokenArray): EncryptedJwtBundle
    {
        return match ($bundle->getHeader()->getType()) {
            self::JWS_TYPE => self::parseSignatureToken($bundle, $tokenArray),
            self::JWE_TYPE => self::parseEncodedToken($bundle, $tokenArray),
            default => throw new InvalidFormatException('Invalid or unsupported token type'),
        };
    }

    /**
     * @param array<int,string> $tokenArray
     */
    private static function parseByStructure(EncryptedJwtBundle $bundle, array $tokenArray): EncryptedJwtBundle
    {
        return match (count($tokenArray)) {
            self::JWS_PART_COUNT => self::parseSignatureToken($bundle, $tokenArray),
            self::JWE_PART_COUNT => self::parseEncodedToken($bundle, $tokenArray),
            default => throw new InvalidFormatException('Invalid or unsupported token type'),
        };
    }

    /**
     * @param array<int,string> $tokenArray
     *
     * @throws InvalidFormatException
     */
    private static function parseEncodedToken(EncryptedJwtBundle $bundle, array $tokenArray): EncryptedJwtBundle
    {
        if (count($tokenArray) !== self::JWE_PART_COUNT) {
            throw new InvalidFormatException('Invalid JWE token structure.');
        }

        // AAD must be the Base64Url-encoded protected header, per RFC 7516 §5.1
        $header = array_shift($tokenArray);
        $bundle->getEncryption()->setAad($header);

        $decoded = [];
        foreach ($tokenArray as $part) {
            $decoded[] = self::decodeBase64Url($part);
        }

        return self::configureFromDecodedData($bundle, $decoded);
    }

    /**
     * @param array<int, string> $decoded
     */
    private static function configureFromDecodedData(EncryptedJwtBundle $bundle, array $decoded): EncryptedJwtBundle
    {
        $encryption = $bundle->getEncryption();
        $header = $bundle->getHeader();

        [$key, $iv, $ciphertext, $authTag] = $decoded;

        // Set key or CEK depending on algorithm
        if ($header->getAlgorithm() === 'dir') {
            $encryption->setCek($key);
        } else {
            $encryption->setEncryptedKey($key);
        }

        // Assign remaining fields
        $bundle->getPayload()->setEncryptedPayload($ciphertext);
        $encryption->setIv($iv)->setAuthTag($authTag);
        return $bundle;
    }

    /**
     * @param array<int,string> $tokenArray
     *
     * @throws InvalidFormatException
     */
    private static function parseSignatureToken(EncryptedJwtBundle $bundle, array $tokenArray): EncryptedJwtBundle
    {
        if (count($tokenArray) !== self::JWS_PART_COUNT) {
            throw new InvalidFormatException('Invalid JWS token structure.');
        }

        $headerB64 = array_shift($tokenArray);

        [$payloadB64] = $tokenArray;

        $aad = "{$headerB64}.{$payloadB64}";

        $decoded = [];
        foreach ($tokenArray as $part) {
            $decoded[] = self::decodeBase64Url($part);
        }

        [$payloadJson, $signature] = $decoded;

        $bundle->getEncryption()->setAad($aad);
        $bundle->setSignature($signature);

        JwtPayloadJsonCodec::decodeStaticInto($payloadJson, $bundle->getPayload());

        return $bundle;
    }

    /**
     * @return string serialized and encoded token
     */
    private static function serializeEncodedToken(EncryptedJwtBundle $bundle): string
    {
        $header = $bundle->getHeader();
        $encryption = $bundle->getEncryption();

        $encryptedKey = match ($header->getAlgorithm()) {
            'dir' => $encryption->getCek(),
            default => $encryption->getEncryptedKey()
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

    private static function serializeSignatureToken(EncryptedJwtBundle $bundle): string
    {
        /*
         * @param array<string> $tokenArray
         */
        $tokenArray = [
            JwtHeaderJsonCodec::encodeStatic($bundle->getHeader()),
            JwtPayloadJsonCodec::encodeStatic($bundle->getPayload()),
            $bundle->getSignature(),
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
                static fn (?string $v): string => Base64UrlEncoder::encode(($v ?? '')),
                $array
            )
        );
    }
}
