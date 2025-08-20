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
    private const DEFAULT_OPTIONS = JSON_THROW_ON_ERROR;

    /**
     * Decodes a JSON string into an associative array or stdClass object.
     *
     * @template TAssoc of bool
     *
     * @param TAssoc $associative When true, returns an associative array; when false, returns an object.
     * @param int    $flags     Additional json_decode flags.
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
        int $flags = self::DEFAULT_DECODE_OPTIONS,
        int $depth = self::DEFAULT_DEPTH
    ): array|stdClass {
        $resolvedDepth = self::assertValidDepth($depth);

        try {
            $result = json_decode($json, $associative, $resolvedDepth, $flags | self::DEFAULT_OPTIONS);
        } catch (JsonException $e) {
            throw new DecodingException($e->getMessage());
        }

        return self::ensureJsonRootIsObjectOrArray($result);
    }

    /**
     * Encodes data to a JSON string.
     *
     * @param array<array-key, mixed>|JsonSerializable $data Data to encode.
     * @param int $flags Additional json_encode flags.
     * @param int $depth   Maximum encoding depth (>= 1).
     *
     * @throws EncodingException
     * @throws InvalidDepthException
     * @throws JsonException
     */
    public static function encode(
        array|JsonSerializable $data,
        int $flags = self::DEFAULT_ENCODE_OPTIONS,
        int $depth = self::DEFAULT_DEPTH
    ): string {
        $resolvedDepth = self::assertValidDepth($depth);
        $value = $data instanceof JsonSerializable ? $data->jsonSerialize() : $data;

        try {
            return json_encode($value, $flags | self::DEFAULT_OPTIONS, $resolvedDepth);
        } catch (JsonException $e) {
            throw new EncodingException($e->getMessage()); // previous setzen
        }
    }

    /**
     * @param mixed $value the unvalidaded type of json answer
     *
     * @return array<mixed>|stdClass the validaed json answer
     *
     * @throws DecodingException
     */
    private static function ensureJsonRootIsObjectOrArray(mixed $value): array|stdClass
    {
        if (! is_array($value) && ! $value instanceof stdClass) {
            throw new DecodingException('Top-level JSON must be an object or array.');
        }
        return $value;
    }

    /**
     * @return int<1, max> positive depth int
     *
     * @throws InvalidDepthException
     */
    private static function assertValidDepth(int $depth): int
    {
        if ($depth < 1) {
            throw new InvalidDepthException($depth);
        }

        return $depth;
    }
}
