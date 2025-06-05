<?php

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use Phithi92\JsonWebToken\JwtHeader;
use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;

/**
 * Description of JwtTokenParser
 *
 * @author phillipthiele
 */
class JwtTokenParser
{
    /**
     *
     * @param string|array<string> $token
     * @return EncryptedJwtBundle
     * @throws InvalidFormatException
     */
    public static function parse(string|array $token): EncryptedJwtBundle
    {
        if (is_string($token)) {
            $tokenParts = explode('.', $token);
        } else {
            $tokenParts = $token;
        }

        $type = self::getType($tokenParts);

        if ($type === 'JWE') {
            return self::parseEncodedToken($tokenParts);
        } elseif ($type === 'JWS') {
            return self::parseSignatureToken($tokenParts);
        } else {
            throw new InvalidFormatException();
        }
    }

    /**
     *
     * @param EncryptedJwtBundle $container
     * @return string
     */
    public static function serialize(EncryptedJwtBundle $container): string
    {
        $type = $container->getHeader()->getType();

        if ($type === 'JWE') {
            return self::serializeEncodedToken($container);
        } elseif ($type === 'JWS') {
            return self::serializeSignatureToken($container);
        } else {
            throw new InvalidFormatException();
        }
    }

    /**
     * @param array<string> $tokenParts
     * @return string
     */
    private static function getType(array $tokenParts): string
    {
        $amount = count($tokenParts);

        // Header immer an erster Stelle
        $headerB64 = $tokenParts[0] ?? '';

        if (!$headerB64) {
            return '';
        }

        $headerJson = Base64UrlEncoder::decode($headerB64, true);
        if (!$headerJson) {
            return '';
        }

        $headerArray = json_decode($headerJson, true);
        if (!is_array($headerArray)) {
            return '';
        }

        // Prüfe ob "typ" im Header gesetzt ist (typischerweise "JWE" oder "JWS")
        if (isset($headerArray['typ'])) {
            $typ = strtoupper($headerArray['typ']);
            if ($typ === 'JWE' && $amount === 5) {
                return 'JWE';
            }
            if ($typ === 'JWS' && $amount === 3) {
                return 'JWS';
            }
            // Falls typ vorhanden, aber Teileanzahl nicht stimmt
            return '';
        }

        // Fallback auf reine Anzahl der Teile (wie bisher)
        if ($amount === 5) {
            return 'JWE';
        }
        if ($amount === 3) {
            return 'JWS';
        }

        return '';
    }
    /**
     * @return EncryptedJwtBundle The initialized JwtTokenContainer.
     * @throws InvalidFormatException If the token format is incorrect.
     * @param array<string> $parts
     */
    private static function parseEncodedToken(array $parts): EncryptedJwtBundle
    {
        [$headerB64, $encryptedKeyB64, $ivB64, $cipherTextB64, $authTagB64] = $parts;
                
        $header = Base64UrlEncoder::decode($headerB64, true);
        $jwtHeader = JwtHeader::fromJson($header);
        $iv = Base64UrlEncoder::decode($ivB64, true);
        $encryptedKey = Base64UrlEncoder::decode($encryptedKeyB64, true);
        $encryptedPayload = Base64UrlEncoder::decode($cipherTextB64, true);
        $authTag = Base64UrlEncoder::decode($authTagB64, true);

        $token = new EncryptedJwtBundle($jwtHeader,new JwtPayload());
        $token->getEncryption()
            ->setIv($iv)
            ->setEncryptedKey($encryptedKey)
            ->setAuthTag($authTag);
        $token
            ->getPayload()
            ->setEncryptedPayload($encryptedPayload);

        return $token;
    }

    /**
     * @return EncryptedJwtBundle The initialized JwtTokenContainer.
     * @throws InvalidFormatException If the token format is incorrect.
     * @param array<string> $parts Description
     */
    private static function parseSignatureToken(array $parts): EncryptedJwtBundle
    {
        [$headerB64, $payloadB64, $signatureB64] = $parts;
        
        $header = Base64UrlEncoder::decode($headerB64, true);
        $payload = Base64UrlEncoder::decode($payloadB64, true);
        $signature = Base64UrlEncoder::decode($signatureB64, true);

        $jwtPayload = JwtPayload::fromJson($payload);
        $jwtHeader = JwtHeader::fromJson($header);

        $container = (new EncryptedJwtBundle($jwtHeader,$jwtPayload))
            ->setSignature($signature);

        return $container;
    }

    /**
     * @return string encoded token.
     * @throws InvalidFormatException If the token format is incorrect.
     */
    private static function serializeEncodedToken(EncryptedJwtBundle $container): string
    {
        $tokenArray = [
            $container->getHeader()->toJson(),
            $container->getEncryption()->getEncryptedKey() ?? $container->getEncryption()->getCek(),
            $container->getEncryption()->getIv() ?? '',
            $container->getPayload()->getEncryptedPayload(),
            $container->getEncryption()->getAuthTag()
        ];

        array_walk($tokenArray, function (&$value) {
            $value = Base64UrlEncoder::encode($value);
        });

        return implode('.', $tokenArray);
    }
    /**
     * @return string encoded token.
     * @throws InvalidFormatException If the token format is incorrect.
     */
    private static function serializeSignatureToken(EncryptedJwtBundle $container): string
    {
        $tokenArray = [
            $container->getHeader()->toJson(),
            $container->getPayload()->getEncryptedPayload() ??
            $container->getPayload()->toJson() ,
            $container->getSignature()
        ];

        array_walk($tokenArray, function (&$value) {
            $value = Base64UrlEncoder::encode($value);
        });

        return implode('.', $tokenArray);
    }
}
