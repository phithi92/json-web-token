<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;

class JwtTokenParser
{
    /**
     * @param string|array<string> $token
     * @return EncryptedJwtBundle
     * @throws InvalidFormatException
     */
    public static function parse(string|array $token): EncryptedJwtBundle
    {
        $parts = is_string($token) ? explode('.', $token) : $token;

        $headerJson = Base64UrlEncoder::decode($parts[0], true);
        $header = JwtHeader::fromJson($headerJson);

        return match ($header->getType()) {
            'JWE' => self::parseEncodedToken($parts),
            'JWS' => self::parseSignatureToken($parts),
            default => throw new InvalidFormatException(),
        };
    }

    /**
     * @param EncryptedJwtBundle $jwtBundle
     * @return string
     * @throws InvalidFormatException
     */
    public static function serialize(EncryptedJwtBundle $jwtBundle): string
    {
        return match ($jwtBundle->getHeader()->getType()) {
            'JWE' => self::serializeEncodedToken($jwtBundle),
            'JWS' => self::serializeSignatureToken($jwtBundle),
            default => throw new InvalidFormatException(),
        };
    }

    /**
     * @param array<string> $parts
     * @return EncryptedJwtBundle
     * @throws InvalidFormatException
     */
    private static function parseEncodedToken(array $parts): EncryptedJwtBundle
    {
        if (count($parts) !== 5) {
            throw new InvalidFormatException();
        }

        [$headerB64, $keyB64, $ivB64, $ciphertextB64, $authTagB64] = $parts;

        $header = JwtHeader::fromJson(Base64UrlEncoder::decode($headerB64, true));
        $key = Base64UrlEncoder::decode($keyB64, true);
        $iv = Base64UrlEncoder::decode($ivB64, true);
        $ciphertext = Base64UrlEncoder::decode($ciphertextB64, true);
        $authTag = Base64UrlEncoder::decode($authTagB64, true);

        $jwtBundle = new EncryptedJwtBundle($header, new JwtPayload());
        $encryption = $jwtBundle->getEncryption();

        // Set CEK or Encrypted Key based on alg
        $isDirectEncryption = $header->getAlgorithm() === 'dir';
        if ($isDirectEncryption) {
            $encryption->setCek($key); // key ist CEK
        } else {
            $encryption->setEncryptedKey($key); // key ist verschlüsselter CEK
        }

        // Always treat ciphertext as encrypted
        $jwtBundle->getPayload()->setEncryptedPayload($ciphertext);

        $encryption
            ->setAad($headerB64)
            ->setIv($iv)
            ->setAuthTag($authTag);

        return $jwtBundle;
    }

    /**
     * @param array<string> $parts
     * @return EncryptedJwtBundle
     * @throws InvalidFormatException
     */
    private static function parseSignatureToken(array $parts): EncryptedJwtBundle
    {
        if (count($parts) !== 3) {
            throw new InvalidFormatException();
        }

        [$headerB64, $payloadB64, $signatureB64] = $parts;

        $headerJson = Base64UrlEncoder::decode($headerB64, true);
        $payloadJson = Base64UrlEncoder::decode($payloadB64, true);
        $signature = Base64UrlEncoder::decode($signatureB64, true);

        $header = JwtHeader::fromJson($headerJson);
        $payload = JwtPayload::fromJson($payloadJson);

        return (new EncryptedJwtBundle($header, $payload))->setSignature($signature);
    }

    /**
     * @param EncryptedJwtBundle $jwtBundle
     * @return string
     */
    private static function serializeEncodedToken(EncryptedJwtBundle $jwtBundle): string
    {
        /** @var string[] $tokenArray */
        $tokenArray = [
            $jwtBundle->getHeader()->toJson(),
            $jwtBundle->getEncryption()->getEncryptedKey() ?? $jwtBundle->getEncryption()->getCek(),
            $jwtBundle->getEncryption()->getIv() ?? '',
            $jwtBundle->getPayload()->getEncryptedPayload() ?? $jwtBundle->getPayload()->toJson(),
            $jwtBundle->getEncryption()->getAuthTag() ?? ''
        ];

        return implode('.', array_map([Base64UrlEncoder::class, 'encode'], $tokenArray));
    }

    /**
     * @param EncryptedJwtBundle $jwtBundle
     * @return string
     */
    private static function serializeSignatureToken(EncryptedJwtBundle $jwtBundle): string
    {
        /** @var string[] $tokenArray */
        $tokenArray = [
            $jwtBundle->getHeader()->toJson(),
            $jwtBundle->getPayload()->toJson(),
            $jwtBundle->getSignature() ?? ''
        ];

        return implode('.', array_map([Base64UrlEncoder::class, 'encode'], $tokenArray));
    }
}
