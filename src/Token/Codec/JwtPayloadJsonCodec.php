<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Codec;

use Phithi92\JsonWebToken\Exceptions\Token\MalformedTokenException;
use Phithi92\JsonWebToken\Interfaces\JwtPayloadCodecInterface;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Throwable;

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
    private const JSON_MAX_DEPTH = 6;

    /**
     * Encode a JwtPayload instance to a JSON string.
     *
     * @param JwtPayload $payload The payload to encode.
     *
     * @return string JSON representation of the payload.
     */
    public function encode(JwtPayload $payload, int $depth = self::JSON_MAX_DEPTH): string
    {
        try {
            return $this->encodeJson($payload->toArray(), $depth);
        } catch (Throwable $e) {
            throw new MalformedTokenException($e->getMessage());
        }
    }

    /**
     * Decode a JSON string into a new JwtPayload instance.
     *
     * @param string $json The JSON string to decode.
     *
     * @return JwtPayload Hydrated JwtPayload instance.
     *
     * @throws MalformedTokenException If the JSON is invalid.
     */
    public function decode(
        string $json,
        int $depth = self::JSON_MAX_DEPTH,
        ?JwtPayload $payload = null
    ): JwtPayload {
        try {
            $data = $this->decodeJson($json, $depth);
        } catch (Throwable $e) {
            throw new MalformedTokenException('Token payload is not valid JSON');
        }

        $payload ??= new JwtPayload();
        $payload->fromArray($data);

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
     * @throws MalformedTokenException If the JSON is invalid.
     */
    public function decodeInto(
        string $json,
        JwtPayload $target,
        int $depth = self::JSON_MAX_DEPTH
    ): void {
        $this->decode($json, $depth, $target);
    }

    /**
     * Encode a payload using a cached codec instance.
     *
     * @param JwtPayload $payload The payload to encode.
     * @param int   $depth   JSON maximum depth, defaults to class constant.
     *
     * @return string JSON representation of the payload.
     */
    public static function encodeStatic(
        JwtPayload $payload,
        int $depth = self::JSON_MAX_DEPTH
    ): string {
        return (new self())->encode($payload, $depth);
    }

    /**
     * Decode a JSON string into a new JwtPayload instance using a cached codec.
     *
     * @param string   $json    The JSON string to decode.
     * @param int $depth   JSON maximum depth, defaults to class constant.
     *
     * @return JwtPayload Hydrated JwtPayload instance.
     *
     * @throws MalformedTokenException If the JSON is invalid.
     */
    public static function decodeStatic(
        string $json,
        int $depth = self::JSON_MAX_DEPTH
    ): JwtPayload {
        return (new self())->decode($json, $depth);
    }

    /**
     * Decode a JSON string into an existing JwtPayload instance using a cached codec.
     *
     * @param string     $json    The JSON string to decode.
     * @param JwtPayload $payload The target instance to populate.
     * @param int   $depth   JSON maximum depth, defaults to class constant.
     *
     * @throws MalformedTokenException If the JSON is invalid.
     */
    public static function decodeStaticInto(
        string $json,
        JwtPayload $payload,
        int $depth = self::JSON_MAX_DEPTH
    ): void {
        (new self())->decodeInto($json, $payload, $depth);
    }
}
