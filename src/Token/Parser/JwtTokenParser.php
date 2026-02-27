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
        $tokenPartCount = count($tokenArray);

        $header = self::buildHeaderFromTokenArray($tokenArray);
        $bundle = new JwtBundle($header);

        if (! is_null($header->getType())) {
            return self::parseByType($bundle, $tokenArray, $tokenPartCount);
        }

        return self::parseByStructure($bundle, $tokenArray, $tokenPartCount);
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
            throw new MalformedTokenException('missing required parts.');
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
            throw new MalformedTokenException('invalid Base64Url encoding.');
        }
    }

    /**
     * @param array<int,string> $tokenArray
     */
    private static function parseByType(JwtBundle $bundle, array $tokenArray, int $tokenPartCount): JwtBundle
    {
        $rawType = $bundle->getHeader()->getType();

        $kind = JwtTokenKind::tryFrom((string) $rawType);
        if ($kind === null) {
            throw new MalformedTokenException('unsupported "typ" header value.');
        }

        return self::parseByKind($bundle, $tokenArray, $kind, $tokenPartCount);
    }

    /**
     * @param array<int,string> $tokenArray
     */
    private static function parseByStructure(JwtBundle $bundle, array $tokenArray, int $tokenPartCount): JwtBundle
    {
        $kind = JwtTokenKind::fromPartCount($tokenPartCount);
        if ($kind === null) {
            throw new MalformedTokenException('unsupported compact serialization.');
        }

        return self::parseByKind($bundle, $tokenArray, $kind, $tokenPartCount);
    }

    /**
     * @param array<int,string> $tokenArray
     *
     * @throws MalformedTokenException
     */
    private static function parseByKind(
        JwtBundle $bundle,
        array $tokenArray,
        JwtTokenKind $kind,
        int $tokenPartCount
    ): JwtBundle {
        if ($tokenPartCount !== $kind->partCount()) {
            throw new MalformedTokenException('invalid number of segments.');
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
            authTag: self::decodeBase64Url($tokenArray[4]),
        );

        if ($bundle->getHeader()->getAlgorithm() === 'dir' && $tokenArray[1] !== '') {
            throw new MalformedTokenException('encrypted key must be empty for "dir" algorithm.');
        }

        if ($bundle->getHeader()->getAlgorithm() !== 'dir') {
            $encryptionData = $encryptionData->withEncryptedKey(
                self::decodeBase64Url($tokenArray[1])
            );
        }

        $encryptedPayload = self::decodeBase64Url($tokenArray[3]);

        $bundle->setEncryption($encryptionData);
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
