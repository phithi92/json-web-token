<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Parser;

use Phithi92\JsonWebToken\Exceptions\Base64\InvalidBase64UrlFormatException;
use Phithi92\JsonWebToken\Exceptions\Token\MalformedTokenException;
use Phithi92\JsonWebToken\Token\Codec\JwtHeaderJsonCodec;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadJsonCodec;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtHeader;
use Phithi92\JsonWebToken\Token\JwtSignature;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;

use function array_map;
use function array_shift;
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
        $tokenArray = is_string($token) ? explode('.', $token) : $token;
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
    private static function configureFromDecodedData(JwtBundle $bundle, array $decoded): JwtBundle
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
     * @throws MalformedTokenException
     */
    private static function parseSignatureToken(JwtBundle $bundle, array $tokenArray): JwtBundle
    {
        if (count($tokenArray) !== self::JWS_PART_COUNT) {
            throw new MalformedTokenException('Invalid JWS token structure.');
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
        $bundle->setSignature(new JwtSignature($signature));

        JwtPayloadJsonCodec::decodeStaticInto($payloadJson, $bundle->getPayload());

        return $bundle;
    }

    /**
     * @return string serialized and encoded token
     */
    private static function serializeEncodedToken(JwtBundle $bundle): string
    {
        $header = $bundle->getHeader();
        $encryption = $bundle->getEncryption();

        $encryptedKey = match ($header->getAlgorithm()) {
            'dir' => $encryption->getCek(),
            default => $encryption->getEncryptedKey(),
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
        /*
         * @param array<string> $tokenArray
         */
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
