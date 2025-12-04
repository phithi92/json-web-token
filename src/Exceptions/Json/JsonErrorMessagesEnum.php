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
enum JsonErrorMessagesEnum: string
{
    use ErrorMessageTrait;

    case DECODING_FAILED = 'JSON decoding failed: %s';
    case ENCODING_FAILED = 'JSON encoding failed: %s';
    case INVALID_LENGTH = 'Invalid depth. %s';
    case UTF8_DECODING = 'JSON got non utf8 data.';
    case MALFORMED_UTF8 = 'Invalid UTF-8 sequence in token payload';
}
