<?php

namespace Phithi92\JsonWebToken\Exception\Token;

use Phithi92\JsonWebToken\Exception\ErrorMessageTrait;

/**
 * Enum for JSON-related error messages.
 *
 * Provides standardized messages for encoding and decoding errors, with
 * optional details for more context.
 */
enum TokenErrorMessages: string
{
    use ErrorMessageTrait;

    case INVALID_SIGNATURE = 'Signature verification failed: The JWT signature is invalid or has been altered.';
    case INVALID_FORMAT = 'string structure is no valid jwt';
}
