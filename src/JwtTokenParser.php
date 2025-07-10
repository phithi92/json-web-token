<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Exceptions\Json\JsonException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;

class JwtTokenParser
{
    private const JWS_PART_COUNT = 3;

    private const JWE_PART_COUNT = 5;

    /**
     * @param string|array<int,string> $token
     *
     * @return EncryptedJwtBundle configured bundle
     *
     * @throws InvalidFormatException
     */
    public static function parse(string|array $token): EncryptedJwtBundle
    {
        $parts = is_string($token) ? explode('.', $token) : $token;
        $partsCount = count($parts);

        $headerB64 = array_shift($parts);
        $headerJson = Base64UrlEncoder::decode($headerB64, true);

        try {
            $header = JwtHeader::fromJson($headerJson);
        } catch (JsonException) {
            throw new InvalidFormatException('Token header is no valid json format');
        }

        $bundle = new EncryptedJwtBundle($header);

        $type = $header->getType();

        if ($type === 'JWS') {
            if ($partsCount !== self::JWS_PART_COUNT) {
                throw new InvalidFormatException('Invalid jws token structure.');
            }

            $payloadB64 = $parts[0];
            $bundle->getEncryption()->setAad(implode('.', [$headerB64,$payloadB64]));

            return self::parseSignatureToken($parts, $bundle);
        }
        if ($type === 'JWE') {
            if ($partsCount !== self::JWE_PART_COUNT) {
                throw new InvalidFormatException('Invalid jwe token structure.');
            }

            $bundle->getEncryption()->setAad($headerB64);

            return self::parseEncodedToken($parts, $bundle);
        }
        throw new InvalidFormatException('Unsupported token type');
    }

    /**
     * @return string Serialized token
     *
     * @throws InvalidFormatException
     */
    public static function serialize(EncryptedJwtBundle $bundle): string
    {
        $type = $bundle->getHeader()->getType();

        return match ($type) {
            'JWE' => self::serializeEncodedToken($bundle),
            'JWS' => self::serializeSignatureToken($bundle),
            default => throw new InvalidFormatException("Unsupported token type: {$type}"),
        };
    }

    /**
     * @param array<string> $parts
     *
     * @throws InvalidFormatException
     */
    private static function parseEncodedToken(array $parts, EncryptedJwtBundle $bundle): EncryptedJwtBundle
    {
        [$keyB64, $ivB64, $ciphertextB64, $authTagB64] = $parts;

        $key = Base64UrlEncoder::decode($keyB64, true);
        $iv = Base64UrlEncoder::decode($ivB64, true);
        $ciphertext = Base64UrlEncoder::decode($ciphertextB64, true);
        $authTag = Base64UrlEncoder::decode($authTagB64, true);

        $encryption = $bundle->getEncryption();
        $header = $bundle->getHeader();

        // Set CEK or Encrypted Key based on alg
        $isDirectEncryption = $header->getAlgorithm() === 'dir';
        if ($isDirectEncryption) {
            $encryption->setCek($key); // key ist CEK
        } else {
            $encryption->setEncryptedKey($key); // key ist verschlüsselter CEK
        }

        $bundle->getPayload()->setEncryptedPayload($ciphertext);

        // Always treat ciphertext as encrypted

        $encryption
            ->setIv($iv)
            ->setAuthTag($authTag);

        return $bundle;
    }

    /**
     * @param array<string> $parts
     *
     * @throws InvalidFormatException
     */
    private static function parseSignatureToken(array $parts, EncryptedJwtBundle $bundle): EncryptedJwtBundle
    {
        [$payloadB64, $signatureB64] = $parts;

        $payloadJson = Base64UrlEncoder::decode($payloadB64, true);
        $signature = Base64UrlEncoder::decode($signatureB64, true);

        $bundle
            ->setSignature($signature)
            ->getPayload()->fromJson($payloadJson);

        return $bundle;
    }

    /**
     * @return string serialized and encoded token
     */
    private static function serializeEncodedToken(EncryptedJwtBundle $bundle): string
    {
        $tokenArray = [
            $bundle->getHeader()->toJson(),
            $bundle->getEncryption()->getEncryptedKey() ?? $bundle->getEncryption()->getCek(),
            $bundle->getEncryption()->getIv() ?? '',
            $bundle->getPayload()->getEncryptedPayload() ?? $bundle->getPayload()->toJson(),
            $bundle->getEncryption()->getAuthTag() ?? '',
        ];

        return self::encodeAndSerialize($tokenArray);
    }

    /**
     * @param EncryptedJwtBundle $jwtBundle
     * @return string
     */
    private static function serializeSignatureToken(EncryptedJwtBundle $bundle): string
    {
        /**
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
     * @param array<int,string> $array
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
