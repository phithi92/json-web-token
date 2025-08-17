<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Codec;

use Phithi92\JsonWebToken\Exceptions\Json\JsonException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;
use Phithi92\JsonWebToken\Interfaces\JwtPayloadCodecInterface;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;

/**
 * Class JwtPayloadJsonCodec
 *
 * Provides JSON encoding and decoding for JwtPayload objects.
 * Supports configurable JSON depth and encoding options, with
 * optional static convenience methods using a cached instance pool
 * for performance in high-throughput scenarios.
 */
final class JwtPayloadJsonCodec extends JwtSegmentJsonCodec implements JwtPayloadCodecInterface
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
     * Internal instance pool keyed by a combination of options and depth.
     * Used to avoid repeated instantiation in static helper methods.
     *
     * @var array<int, self>
     */
    private static array $pool = [];

    /**
     * Constructor.
     *
     * @param int $depth   Maximum depth for JSON encoding/decoding.
     * @param int $options Bitmask of JSON encoding options.
     */
    public function __construct(
        public readonly int $depth = self::JSON_DEPTH,
        public readonly int $options = self::JSON_OPTIONS,
    ) {
        parent::__construct();
    }

    /**
     * Encode a JwtPayload instance to a JSON string.
     *
     * @param JwtPayload $payload The payload to encode.
     *
     * @return string JSON representation of the payload.
     */
    public function encode(JwtPayload $payload): string
    {
        return JsonEncoder::encode($payload->toArray(), $this->options, $this->depth);
    }

    /**
     * Decode a JSON string into a new JwtPayload instance.
     *
     * @param string $json The JSON string to decode.
     *
     * @return JwtPayload Hydrated JwtPayload instance.
     *
     * @throws InvalidFormatException If the JSON is invalid.
     */
    public function decode(string $json): JwtPayload
    {
        $payload = new JwtPayload();
        $payload->fromArray($this->decodeJson($json));

        return $payload;
    }

    /**
     * Decode a JSON string into an existing JwtPayload instance.
     *
     * This method avoids creating a new JwtPayload object, which
     * can be beneficial in high-performance scenarios.
     *
     * @param string     $json   The JSON string to decode.
     * @param JwtPayload $target The target instance to populate.
     *
     * @throws InvalidFormatException If the JSON is invalid.
     */
    public function decodeInto(string $json, JwtPayload $target): void
    {
        $target->fromArray($this->decodeJson($json));
    }

    /**
     * Encode a payload using a cached codec instance.
     *
     * @param JwtPayload $payload The payload to encode.
     * @param int|null   $options JSON encoding options, defaults to class constant.
     * @param int|null   $depth   JSON maximum depth, defaults to class constant.
     *
     * @return string JSON representation of the payload.
     */
    public static function encodeStatic(
        JwtPayload $payload,
        ?int $options = null,
        ?int $depth = null
    ): string {
        $inst = self::instance($options ?? self::JSON_OPTIONS, $depth ?? self::JSON_DEPTH);

        return $inst->encode($payload);
    }

    /**
     * Decode a JSON string into a new JwtPayload instance using a cached codec.
     *
     * @param string   $json    The JSON string to decode.
     * @param int|null $options JSON encoding options, defaults to class constant.
     * @param int|null $depth   JSON maximum depth, defaults to class constant.
     *
     * @return JwtPayload Hydrated JwtPayload instance.
     *
     * @throws InvalidFormatException If the JSON is invalid.
     */
    public static function decodeStatic(
        string $json,
        ?int $options = null,
        ?int $depth = null
    ): JwtPayload {
        $inst = self::instance($options ?? self::JSON_OPTIONS, $depth ?? self::JSON_DEPTH);

        return $inst->decode($json);
    }

    /**
     * Decode a JSON string into an existing JwtPayload instance using a cached codec.
     *
     * @param string     $json    The JSON string to decode.
     * @param JwtPayload $payload The target instance to populate.
     * @param int|null   $options JSON encoding options, defaults to class constant.
     * @param int|null   $depth   JSON maximum depth, defaults to class constant.
     *
     * @throws InvalidFormatException If the JSON is invalid.
     */
    public static function decodeStaticInto(
        string $json,
        JwtPayload $payload,
        ?int $options = null,
        ?int $depth = null
    ): void {
        $inst = self::instance($options ?? self::JSON_OPTIONS, $depth ?? self::JSON_DEPTH);
        $inst->decodeInto($json, $payload);
    }

    /**
     * Decode a JSON string into an associative array.
     *
     * @param string $json The JSON string to decode.
     *
     * @return array<mixed> The decoded data.
     *
     * @throws InvalidFormatException If the JSON cannot be decoded.
     */
    private function decodeJson(string $json): array
    {
        try {
            /** @var array<mixed> */
            return JsonEncoder::decode($json, true, 0, $this->depth);
        } catch (JsonException) {
            throw new InvalidFormatException('Token payload is not valid JSON');
        }
    }

    /**
     * Retrieve or create a cached instance for the given configuration.
     *
     * @param int $options JSON encoding options.
     * @param int $depth   JSON maximum depth.
     */
    private static function instance(int $options, int $depth): self
    {
        // Combine options and depth into a single integer key for fast lookup
        $key = ($options << 8) | ($depth & 0xFF);

        return self::$pool[$key] ??= new self($depth + 1, $options);
    }
}
