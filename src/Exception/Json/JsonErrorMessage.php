<?php

namespace Phithi92\JsonWebToken\Exception\Json;

use Phithi92\JsonWebToken\Exception\ErrorMessageTrait;

/**
 * Enum for JSON-related error messages.
 *
 * Provides standardized messages for encoding and decoding errors, with
 * optional details for more context.
 */
enum JsonErrorMessage: string
{
    use ErrorMessageTrait;

    case DecodingFailed = 'JSON decoding failed: %s';
    case EncodingFailed = 'JSON encoding failed: %s';
}
