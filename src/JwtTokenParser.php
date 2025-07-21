<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Exceptions\Json\JsonException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;
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
        $tokenArray = is_string($token) ? explode('.', $token) : $token;
        if (! isset($tokenArray[0])) {
            throw new InvalidFormatException('Token is malformed or incomplete');
        }

        $headerB64 = $tokenArray[0];
        $headerJson = Base64UrlEncoder::decode($headerB64, true);

        try {
            $header = JwtHeader::fromJson($headerJson);
        } catch (JsonException) {
            throw new InvalidFormatException('Token header is not valid JSON');
        }

        $bundle = new EncryptedJwtBundle($header);

        $typ = $header->getType();
        if (! is_null($typ)) {
            return match ($typ) {
                self::JWS_TYPE => self::parseSignatureToken($bundle, $tokenArray),
                self::JWE_TYPE => self::parseEncodedToken($bundle, $tokenArray),
                default => throw new InvalidFormatException('Invalid or unsupported token type'),
            };
        }

        $parts = count($tokenArray);
        return match ($parts) {
            self::JWS_PART_COUNT => self::parseSignatureToken($bundle, $tokenArray),
            self::JWE_PART_COUNT => self::parseEncodedToken($bundle, $tokenArray),
            default => throw new InvalidFormatException('Invalid or unsupported token type'),
        };
    }

    /**
     * @return string Serialized token
     *
     * @throws InvalidFormatException
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
     * @param array<int,string> $tokenArray
     *
     * @throws InvalidFormatException
     */
    private static function parseEncodedToken(EncryptedJwtBundle $bundle, array $tokenArray): EncryptedJwtBundle
    {
        if (count($tokenArray) !== self::JWE_PART_COUNT) {
            throw new InvalidFormatException('Invalid JWE token structure.');
        }

        [
            $headerB64,
            $keyB64,
            $ivB64,
            $ciphertextB64,
            $authTagB64,
        ] = $tokenArray;

        $encryption = $bundle->getEncryption();
        $header = $bundle->getHeader();

        $decoded = [
            'key' => Base64UrlEncoder::decode($keyB64, true),
            'iv' => Base64UrlEncoder::decode($ivB64, true),
            'ciphertext' => Base64UrlEncoder::decode($ciphertextB64, true),
            'authTag' => Base64UrlEncoder::decode($authTagB64, true),
        ];

        // Set key or CEK depending on algorithm
        if ($header->getAlgorithm() === 'dir') {
            $encryption->setCek($decoded['key']);
        } else {
            $encryption->setEncryptedKey($decoded['key']);
        }

        // Assign remaining fields
        $bundle->getPayload()->setEncryptedPayload($decoded['ciphertext']);
        $encryption->setIv($decoded['iv'])->setAuthTag($decoded['authTag'])->setAad($headerB64);
        // Preserve header for verification
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

        [
            $headerB64,
            $payloadB64,
            $signatureB64,
        ] = $tokenArray;

        $aad = "{$headerB64}.{$payloadB64}";
        $payloadJson = Base64UrlEncoder::decode($payloadB64, true);
        $signature = Base64UrlEncoder::decode($signatureB64, true);

        $bundle->getEncryption()->setAad($aad);
        $bundle->setSignature($signature);
        $bundle->getPayload()->fromJson($payloadJson);

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
            $bundle->getHeader()->toJson(),
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
         * @param string<string> $tokenArray
         */
        $tokenArray = [
            $bundle->getHeader()->toJson(),
            $bundle->getPayload()->toJson(),
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
