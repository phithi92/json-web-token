<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Utilities;

use Phithi92\JsonWebToken\Exceptions\Base64\InvalidBase64UrlFormatException;

use function base64_decode;
use function base64_encode;
use function rtrim;
use function strlen;
use function strtr;
use function substr;

/**
 * Base64 URL-safe encoding/decoding (RFC 7515 §2).
 */
final class Base64UrlEncoder
{
    public static function encode(string $data): string
    {
        // base64 -> url-safe + without padding
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function decode(string $base64Url): string
    {
        // url-safe -> base64
        $base64 = strtr($base64Url, '-_', '+/');

        // add missing padding (only 0–2 '=' characters are possible)
        $rem = strlen($base64) & 3;

        if ($rem === 1) {
            throw new InvalidBase64UrlFormatException('Invalid Base64Url input: invalid length');
        }

        if ($rem !== 0) {
            $base64 .= $rem === 2 ? '==' : '=';
        }

        $decoded = base64_decode($base64, true);
        if ($decoded === false) {
            $len = strlen($base64Url);
            $snippet = substr($base64Url, 0, 30) . ($len > 30 ? '...' : '');
            throw new InvalidBase64UrlFormatException('Invalid Base64Url input: "' . $snippet . '"');
        }

        return $decoded;
    }
}
