<?php

namespace Phithi92\JsonWebToken\Utilities;

use Phithi92\JsonWebToken\Exceptions\Json\DecodingException;
use Phithi92\JsonWebToken\Exceptions\Json\EncodingException;
use stdClass;

/**
 * Class JsonEncoder
 *
 * Provides static methods for encoding arrays to JSON strings and decoding JSON strings to arrays.
 * Handles errors by throwing DecodingException and EncodingException, which both extend JsonException.
 *
 * Methods:
 * - decode(string $json): Decodes a JSON string into an associative array. Throws DecodingException on failure.
 * - encode(array $array): Encodes an associative array into a JSON string. Throws EncodingException on failure.
 *
 * @package json-web-token\Utilities
 * @author Phillip Thiele <development@phillip-thiele.de>
 * @version 1.0.0
 * @since 1.0.0
 * @license https://github.com/phithi92/json-web-token/blob/main/LICENSE MIT License
 * @link https://github.com/phithi92/json-web-token Project on GitHub
 */
class JsonEncoder
{
    /**
     * Decodes a JSON-encoded string into an associative array.
     *
     * Uses json_decode to parse the JSON string. If decoding fails, it throws
     * a DecodingException to indicate an error.
     *
     * @param  string $json The JSON-encoded string to decode.
     * @return array The decoded associative array.
     * @throws DecodingException if the JSON string cannot be decoded.
     */
    public static function decode(string $json, bool $associative = false): array|stdClass
    {
        $decoded = json_decode($json, $associative);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new DecodingException();
        }
        return $decoded;
    }

    /**
     * Encodes an associative array into a JSON string.
     *
     * Uses json_encode to convert the array to JSON. If encoding fails,
     * it throws an EncodingException to indicate an error.
     *
     * @param  array $array The associative array to encode.
     * @return string The JSON-encoded string.
     * @throws EncodingException if the array cannot be encoded to JSON.
     */
    public static function encode(array $array): string
    {
        $encoded = json_encode($array);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new EncodingException();
        }
        return $encoded;
    }
}
