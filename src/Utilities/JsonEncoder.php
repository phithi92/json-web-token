<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Utilities;

use JsonException;
use JsonSerializable;
use Phithi92\JsonWebToken\Exceptions\Json\DecodingException;
use Phithi92\JsonWebToken\Exceptions\Json\EncodingException;
use Phithi92\JsonWebToken\Exceptions\Json\InvalidDepthException;
use stdClass;

final class JsonEncoder
{
    private const DEFAULT_DEPTH = 512;
    private const DEFAULT_ENCODE_OPTIONS = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;
    private const DEFAULT_DECODE_OPTIONS = 0;

    /**
     * Decodes a JSON string into an associative array or stdClass object.
     *
     * @template TAssoc of bool
     *
     * @param TAssoc $associative When true, returns an associative array; when false, returns an object.
     * @param int    $options     Additional json_decode flags.
     * @param int    $depth       Maximum decoding depth (>= 1).
     *
     * @return (TAssoc is true ? array<mixed> : stdClass)
     *
     * @throws DecodingException
     * @throws InvalidDepthException
     */
    public static function decode(
        string $json,
        bool $associative = false,
        int $options = self::DEFAULT_DECODE_OPTIONS,
        int $depth = self::DEFAULT_DEPTH
    ): array|stdClass {
        $resolvedDepth = self::validatedDepth($depth);

        try {
            return self::decodeJson($json, $associative, $resolvedDepth, $options);
        } catch (JsonException $e) {
            throw new DecodingException($e->getMessage());
        }
    }

    /**
     * Encodes data to a JSON string.
     *
     * @param array<mixed>|JsonSerializable $data Data to encode.
     * @param int $options Additional json_encode flags.
     * @param int $depth   Maximum encoding depth (>= 1).
     *
     * @throws EncodingException
     * @throws InvalidDepthException
     */
    public static function encode(
        array|JsonSerializable $data,
        int $options = self::DEFAULT_ENCODE_OPTIONS,
        int $depth = self::DEFAULT_DEPTH
    ): string {
        $resolvedDepth = self::validatedDepth($depth);

        return self::encodeJson($data, $options, $resolvedDepth);
    }

    /**
     * @template TAssoc of bool
     *
     * @param TAssoc $associative When true, returns an associative array; when false, returns an object.
     * @param int<1,max> $depth   Maximum decoding depth.
     * @param int $flags        Flags for json_decode.
     *
     * @return (TAssoc is true ? array<mixed> : stdClass)
     *
     * @throws JsonException
     * @throws DecodingException
     */
    private static function decodeJson(string $json, bool $associative, int $depth, int $flags): array|stdClass
    {
        $result = json_decode($json, $associative, $depth, $flags | JSON_THROW_ON_ERROR);

        if ($associative) {
            return self::validatedArray($result);
        }

        if (! $result instanceof stdClass) {
            throw new DecodingException('Expected top-level JSON object when $associative=false.');
        }

        return $result;
    }

    /**
     * @return array<mixed>
     *
     * @throws DecodingException
     */
    private static function validatedArray(mixed $array): array
    {
        if (! is_array($array)) {
            throw new DecodingException('Expected top-level JSON array when $associative=true.');
        }

        return $array;
    }

    /**
     * @param array<mixed>|JsonSerializable $value
     * @param int<1, max> $depth
     *
     * @return string json encoded string
     *
     * @throws JsonException
     * @throws EncodingException
     */
    private static function encodeJson(array|JsonSerializable $value, int $flags, int $depth): string
    {
        if ($value instanceof JsonSerializable) {
            $value = $value->jsonSerialize();
        }

        // json encode return string, otherwise throw JsonException on error.
        return json_encode($value, $flags | JSON_THROW_ON_ERROR, $depth);
    }

    /**
     * @return int<1, max> positive depth int
     *
     * @throws InvalidDepthException
     */
    private static function validatedDepth(?int $depth = null): int
    {
        if (! is_int($depth) || $depth < 1) {
            $resolvedDepth = is_int($depth) ? $depth : 0;
            throw new InvalidDepthException($resolvedDepth);
        }

        return $depth;
    }
}
