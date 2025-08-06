<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Utilities;

use Phithi92\JsonWebToken\Exceptions\Base64\InvalidBase64UrlFormatException;

/**
 * Encodes and decodes data using Base64 URL-safe format as defined in RFC 7515 §2.
 * Replaces unsafe characters and removes padding for safe transmission in URLs or JWTs.
 */
final class Base64UrlEncoder
{
    /**
     * Encodes data to Base64 URL format according to the RFC 7515 standard.
     *
     * @param string $data The data to encode.
     *
     * @return string The Base64 URL-encoded string.
     */
    public static function encode(string $data): string
    {
        $base64 = self::encodeBase64($data);
        return self::convertBase64ToUrlSafe($base64);
    }

    /**
     * Decodes a Base64 URL-encoded string.
     *
     * @param string $base64Url The Base64 URL-encoded data to decode.
     *
     * @return string The decoded data.
     */
    public static function decode(string $base64Url): string
    {
        $base64 = self::convertUrlSafeToBase64($base64Url);
        return self::decodeBase64($base64);
    }

    private static function addPaddingIfMissing(string $string): string
    {
        $remainder = strlen($string) % 4;
        if ($remainder > 0) {
            $string .= str_repeat('=', 4 - $remainder);
        }

        return $string;
    }

    private static function convertUrlSafeToBase64(string $base64Url): string
    {
        $base64 = strtr($base64Url, '-_', '+/');

        return self::addPaddingIfMissing($base64);
    }

    private static function convertBase64ToUrlSafe(string $string): string
    {
        return rtrim(strtr($string, '+/', '-_'), '=');
    }

    private static function decodeBase64(string $base64): string
    {
        $decoded = base64_decode($base64, true);
        if ($decoded === false) {
            $snippet = substr($base64, 0, 30) . (strlen($base64) > 30 ? '...' : '');
            throw new InvalidBase64UrlFormatException(
                sprintf('Invalid Base64Url input: "%s"', $snippet)
            );
        }

        return $decoded;
    }

    private static function encodeBase64(string $string): string
    {
        return base64_encode($string);
    }
}
