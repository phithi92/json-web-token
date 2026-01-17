<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Codec;

use Phithi92\JsonWebToken\Exceptions\Json\DecodingException;
use Phithi92\JsonWebToken\Exceptions\Json\EncodingException;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;

abstract class AbstractJwtSegmentJsonCodec
{
    /** @var array<class-string, self> */
    private static array $sharedInstances = [];

    /**
     * Default JSON encoding options.
     *
     * - JSON_UNESCAPED_SLASHES: Prevents escaping of slashes.
     * - JSON_UNESCAPED_UNICODE: Prevents escaping of multibyte Unicode characters.
     */
    protected const DEFAULT_JSON_OPTIONS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;

    /**
     * @param array<string,mixed> $segment
     *
     * @throws EncodingException
     */
    protected function encodeJson(
        array $segment,
        int $depth,
        int $options = self::DEFAULT_JSON_OPTIONS,
    ): string {
        return JsonEncoder::encode(
            $segment,
            $options,
            $depth
        );
    }

    /**
     * @return array<mixed>
     *
     * @throws DecodingException
     */
    protected function decodeJson(
        string $json,
        int $depth,
        int $options = self::DEFAULT_JSON_OPTIONS,
    ): array {
        return JsonEncoder::decode(
            $json,
            true,
            $options,
            $depth
        );
    }
    
    protected static function shared(): static
    {
        return self::$sharedInstances[static::class] ??= new static();
    }
}
