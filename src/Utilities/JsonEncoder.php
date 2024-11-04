<?php

namespace Phithi92\JsonWebToken\Utilities;

use Phithi92\JsonWebToken\Exception\Json\DecodingException;
use Phithi92\JsonWebToken\Exception\Json\EncodingException;

/**
 * Description of JsonEncoder
 *
 * @author phillip
 */
class JsonEncoder
{
    /**
     *
     * @param  string $json
     * @return array
     * @throws InvalidToken
     */
    public static function decode(string $json): array
    {
        $decoded = json_decode($json, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new DecodingException();
        }
        return $decoded;
    }

    public static function encode(array $array): string
    {
        $encoded = json_encode($array);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new EncodingException();
        }
        return $encoded;
    }
}
