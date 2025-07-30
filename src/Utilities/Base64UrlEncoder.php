<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Utilities;

use Phithi92\JsonWebToken\Exceptions\Base64\InvalidBase64UrlFormatException;

/**
 * Class Base64UrlEncoder
 *
 * Provides methods for encoding and decoding data in a Base64 URL-safe format,
 * compliant with the RFC 7515 standard. This class is useful for encoding data
 * that needs to be included in URLs, ensuring compatibility by using URL-safe
 * characters and omitting padding characters.
 *
 * - `encode(string $string): string`: Encodes data to a Base64 URL-safe string.
 * - `decode(string $string, bool $padding = false): string`: Decodes a Base64 URL-safe
 *   string back to its original form, with optional padding for compatibility.
 */
final class Base64UrlEncoder
{
    /**
     * Encodes data to Base64 URL format according to the RFC 7515 standard.
     *
     * @param string $string The data to encode.
     *
     * @return string The Base64 URL-encoded string.
     */
    public static function encode(string $string): string
    {
        // Base64 encode the data and format it for URL compatibility
        $base64 = base64_encode($string);
        return rtrim(strtr($base64, '+/', '-_'), '=');
    }

    /**
     * Decodes a Base64 URL-encoded string.
     *
     * @param string $string  The Base64 URL-encoded data to decode.
     * @param bool   $padding Optional flag to add padding characters.
     *
     * @return string The decoded data.
     */
    public static function decode(string $string, bool $padding = false): string
    {
        // add optional padding
        $remainder = strlen($string) % 4;
        if ($padding && $remainder > 0) {
            $string .= str_repeat('=', 4 - $remainder);
        }

        // Base64URL to Base64
        $base64 = strtr($string, '-_', '+/');

        // decode
        $decoded = base64_decode($base64, true);

        if ($decoded === false) {
            $snippet = substr($string, 0, 30) . (strlen($string) > 30 ? '...' : '');
            throw new InvalidBase64UrlFormatException(
                sprintf('Invalid Base64Url input: "%s"', $snippet)
            );
        }

        return $decoded;
    }
}
