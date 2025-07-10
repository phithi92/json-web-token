<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Json;

use Phithi92\JsonWebToken\Exceptions\ErrorMessageTrait;

/**
 * Enum for JSON-related error messages.
 *
 * Provides standardized messages for encoding and decoding errors, with
 * optional details for more context.
 */
enum ErrorMessagesEnum: string
{
    use ErrorMessageTrait;

    case DecodingFailed = 'JSON decoding failed: %s';
    case EncodingFailed = 'JSON encoding failed: %s';
    case INVALID_LENGTH = 'Invalid depth. %s';
}
