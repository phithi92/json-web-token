<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Codec;

use Phithi92\JsonWebToken\Exceptions\Json\JsonException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;
use Phithi92\JsonWebToken\Interfaces\JwtHeaderCodecInterface;
use Phithi92\JsonWebToken\Token\JwtHeader;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;

/**
 * Class JwtHeaderJsonCodec
 *
 * Provides JSON encoding and decoding for JwtHeader objects.
 * Supports configurable JSON depth with optional static convenience
 * methods for quick one-off operations.
 */
final class JwtHeaderJsonCodec extends JwtSegmentJsonCodec implements JwtHeaderCodecInterface
{
    /**
     * Default JSON encoding options.
     *
     * - JSON_UNESCAPED_SLASHES: Prevents escaping of slashes.
     * - JSON_UNESCAPED_UNICODE: Prevents escaping of multibyte Unicode characters.
     */
    private const JSON_OPTIONS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;

    /**
     * Default maximum depth for JSON encoding/decoding.
     */
    private const JSON_DEPTH = 3;

    /**
     * Encode a JwtHeader instance to a JSON string.
     *
     * @param JwtHeader $header The header instance to encode.
     * @param int|null  $depth  Optional maximum depth for encoding; defaults to class constant.
     *
     * @return string JSON representation of the header.
     */
    public function encode(JwtHeader $header, ?int $depth = null): string
    {
        try {
            return JsonEncoder::encode($header, self::JSON_OPTIONS, $depth ?? self::JSON_DEPTH);
        } catch (JsonException $e) {
            $this->jsonErrorTranslator->rethrow($e, $depth, InvalidFormatException::class);
        }
    }

    /**
     * Decode a JSON string into a JwtHeader instance.
     *
     * @param string   $json  The JSON string to decode.
     * @param int|null $depth Optional maximum depth for decoding; defaults to class constant.
     *
     * @return JwtHeader Hydrated JwtHeader instance.
     *
     * @throws InvalidFormatException If the JSON cannot be decoded into a valid JwtHeader.
     */
    public function decode(string $json, ?int $depth = null): JwtHeader
    {
        try {
            /** @var array<string, mixed> $data */
            $data = JsonEncoder::decode($json, true, 0, $depth ?? self::JSON_DEPTH);
        } catch (JsonException $e) {
            $this->jsonErrorTranslator->rethrow($e, $depth, InvalidFormatException::class);
        }

        return JwtHeader::fromArray($data);
    }

    /**
     * Static convenience method to encode a JwtHeader to JSON.
     * Creates a new codec instance internally.
     *
     * @param JwtHeader $header The header instance to encode.
     * @param int|null  $depth  Optional maximum depth for encoding; defaults to class constant.
     *
     * @return string JSON representation of the header.
     */
    public static function encodeStatic(JwtHeader $header, ?int $depth = null): string
    {
        return (new self())->encode($header, $depth ?? self::JSON_DEPTH);
    }

    /**
     * Static convenience method to decode JSON into a JwtHeader.
     * Creates a new codec instance internally.
     *
     * @param string   $json  The JSON string to decode.
     * @param int|null $depth Optional maximum depth for decoding; defaults to class constant.
     *
     * @return JwtHeader Hydrated JwtHeader instance.
     *
     * @throws InvalidFormatException If the JSON cannot be decoded into a valid JwtHeader.
     */
    public static function decodeStatic(string $json, ?int $depth = null): JwtHeader
    {
        return (new self())->decode($json, $depth ?? self::JSON_DEPTH);
    }
}
