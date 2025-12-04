<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Codec;

use Phithi92\JsonWebToken\Exceptions\Token\MalformedTokenException;
use Phithi92\JsonWebToken\Interfaces\JwtHeaderCodecInterface;
use Phithi92\JsonWebToken\Token\JwtHeader;
use Throwable;

/**
 * Class JwtHeaderJsonCodec
 *
 * Provides JSON encoding and decoding for JwtHeader objects.
 * Supports configurable JSON depth with optional static convenience
 * methods for quick one-off operations.
 */
final class JwtHeaderJsonCodec extends JwtSegmentJsonCodec implements JwtHeaderCodecInterface
{
    private const MAX_JSON_DEPTH = 3;

    /**
     * Encode a JwtHeader instance to a JSON string.
     *
     * @param JwtHeader $header The header instance to encode.
     * @param int  $depth  Optional maximum depth for encoding; defaults to class constant.
     *
     * @return string JSON representation of the header.
     *
     * @throws MalformedTokenException If the JwtHeader cannot be encoded into a valid json.
     */
    public function encode(JwtHeader $header, int $depth = self::MAX_JSON_DEPTH): string
    {
        try {
            return $this->encodeJson($header->toArray(), $depth);
        } catch (Throwable $e) {
            throw new MalformedTokenException($e->getMessage());
        }
    }

    /**
     * Decode a JSON string into a JwtHeader instance.
     *
     * @param string   $json  The JSON string to decode.
     * @param int $depth Optional maximum depth for decoding; defaults to class constant.
     *
     * @return JwtHeader Hydrated JwtHeader instance.
     *
     * @throws MalformedTokenException If the JSON cannot be decoded into a valid JwtHeader.
     */
    public function decode(string $json, int $depth = self::MAX_JSON_DEPTH): JwtHeader
    {
        try {
            $data = $this->decodeJson($json, $depth);
        } catch (Throwable) {
            throw new MalformedTokenException('Header is not valid JSON');
        }

        return JwtHeader::fromArray($data);
    }

    /**
     * Static convenience method to encode a JwtHeader to JSON.
     * Creates a new codec instance internally.
     *
     * @param JwtHeader $header The header instance to encode.
     * @param int  $depth  Optional maximum depth for encoding; defaults to class constant.
     *
     * @return string JSON representation of the header.
     */
    public static function encodeStatic(JwtHeader $header, int $depth = self::MAX_JSON_DEPTH): string
    {
        return (new self())->encode($header, $depth);
    }

    /**
     * Static convenience method to decode JSON into a JwtHeader.
     * Creates a new codec instance internally.
     *
     * @param string   $json  The JSON string to decode.
     * @param int $depth Optional maximum depth for decoding; defaults to class constant.
     *
     * @return JwtHeader Hydrated JwtHeader instance.
     *
     * @throws MalformedTokenException If the JSON cannot be decoded into a valid JwtHeader.
     */
    public static function decodeStatic(string $json, int $depth = self::MAX_JSON_DEPTH): JwtHeader
    {
        return (new self())->decode($json, $depth);
    }
}
