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
use Phithi92\JsonWebToken\Token\JwtTokenKind;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;

use function count;
use function explode;
use function is_null;
use function is_string;

final class JwtTokenParser
{
    /**
     * @param string|array<int,string> $token
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
     * @param string|array<int,string> $token
     *
     * @return array<int,string>
     *
     * @throws MalformedTokenException
     */
    private static function normalizeTokenInput(string|array $token): array
    {
        // limit=6: detect "too many dots" by grouping extras into last element
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
        $rawType = $bundle->getHeader()->getType();

        $kind = JwtTokenKind::tryFrom((string) $rawType);
        if ($kind === null) {
            throw new MalformedTokenException('Invalid or unsupported token type');
        }

        return self::parseByKind($bundle, $tokenArray, $kind);
    }

    /**
     * @param array<int,string> $tokenArray
     */
    private static function parseByStructure(JwtBundle $bundle, array $tokenArray): JwtBundle
    {
        $kind = JwtTokenKind::fromPartCount(count($tokenArray));

        if ($kind === null) {
            throw new MalformedTokenException('Invalid or unsupported token type');
        }

        return self::parseByKind($bundle, $tokenArray, $kind);
    }

    /**
     * @param array<int,string> $tokenArray
     *
     * @throws MalformedTokenException
     */
    private static function parseByKind(JwtBundle $bundle, array $tokenArray, JwtTokenKind $kind): JwtBundle
    {
        if (count($tokenArray) !== $kind->partCount()) {
            throw new MalformedTokenException('Invalid token structure.');
        }

        return $kind->isSignatureToken()
            ? self::parseSignatureToken($bundle, $tokenArray)
            : self::parseEncodedToken($bundle, $tokenArray);
    }

    /**
     * @param array<int,string> $tokenArray
     *
     * @throws MalformedTokenException
     */
    private static function parseEncodedToken(JwtBundle $bundle, array $tokenArray): JwtBundle
    {
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
        $bundle->setEncryption(new JwtEncryptionData(aad: $tokenArray[0] . '.' . $tokenArray[1]));

        $signature = self::decodeBase64Url($tokenArray[2]);
        $bundle->setSignature(new JwtSignature($signature));

        $payloadJson = self::decodeBase64Url($tokenArray[1]);
        JwtPayloadJsonCodec::decodeStaticInto($payloadJson, $bundle->getPayload());

        return $bundle;
    }
}
