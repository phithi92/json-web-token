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
 * @package Phithi92\JsonWebToken\Utilities
 * @author Phillip Thiele <development@phillip-thiele.de>
 * @version 1.0.0
 * @since 1.0.0
 * @license https://github.com/phithi92/json-web-token/blob/main/LICENSE MIT License
 * @link https://github.com/phithi92/json-web-token Project on GitHub
 */
class JsonEncoder
{
    /**
     * Decodes a JSON-encoded string into an associative array or stdClass object.
     *
     * This method uses json_decode with JSON_THROW_ON_ERROR and any additional flags passed
     * through the $options parameter to parse the JSON string. The JSON_THROW_ON_ERROR flag 
     * ensures that any errors in decoding throw a JsonException, which is caught and rethrown 
     * as a DecodingException for more specific error handling.
     *
     * @param string $json The JSON-encoded string to decode.
     * @param bool $associative When true, returns an associative array; when false, returns an stdClass object.
     * @param int $options Additional JSON decode options (e.g., JSON_BIGINT_AS_STRING), combined with JSON_THROW_ON_ERROR.
     * @param int $depth The maximum depth for JSON decoding. Defaults to 512.
     * @return array|stdClass The decoded data, either as an associative array or stdClass object.
     * @throws DecodingException if the JSON string cannot be decoded.
     */
    public static function decode(string $json, bool $associative = false, int $options = 0, int $depth = 512): array|stdClass
    {
        $flags = JSON_THROW_ON_ERROR | $options;

        try {
            return json_decode($json, $associative, $depth, $flags);
        } catch (JsonException $e) {
            throw new DecodingException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Encodes an associative array into a JSON string.
     *
     * This method uses json_encode with JSON_THROW_ON_ERROR and any additional flags passed 
     * through the $options parameter to convert the array to JSON format. The JSON_THROW_ON_ERROR 
     * flag ensures that any errors in encoding throw a JsonException, which is caught and rethrown 
     * as an EncodingException for more specific error handling.
     *
     * @param array $array The associative array to encode.
     * @param int $options Additional JSON encode options (e.g., JSON_UNESCAPED_UNICODE), combined with JSON_THROW_ON_ERROR.
     * @param int $depth The maximum depth for JSON encoding. Defaults to 512.
     * @return string The JSON-encoded string.
     * @throws EncodingException if the array cannot be encoded to JSON.
     */
    public static function encode(array $array, int $options = 0, int $depth = 512): string
    {
        $flags = JSON_THROW_ON_ERROR | $options;

        try {
            return json_encode($array, $flags, $depth);
        } catch (JsonException $e) {
            throw new EncodingException($e->getMessage(), $e->getCode(), $e);
        }
    }
}
