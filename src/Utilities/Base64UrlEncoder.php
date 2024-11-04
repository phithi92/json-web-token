<?php

namespace Phithi92\JsonWebToken\Utilities;

/**
 * Description of Base64UrlEncoder
 *
 * @author phillip
 */

class Base64UrlEncoder
{
    /**
     * Encodes data to Base64 URL format according to the RFC 7515 standard.
     *
     * @param  string $string The data to encode.
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
     * @param  string $string  The Base64 URL-encoded data to decode.
     * @param  bool   $padding Optional flag to add padding characters.
     * @return string The decoded data.
     */
    public static function decode(string $string, bool $padding = false): string
    {
        $remainder = strlen($string) % 4;
        if ($padding && $remainder > 0) {
            $string .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($string, '-_', '+/'));
    }
}
