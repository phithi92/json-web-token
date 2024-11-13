<?php

namespace Phithi92\JsonWebToken\Exceptions\Token;

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

    case INVALID_SIGNATURE = 'Signature verification failed: The JWT signature is invalid or has been altered.';
    case INVALID_FORMAT = 'string structure is no valid jwt';
    case INVALID_TOKEN = 'Token is not valid.';
    case INVALID_AUTH_TAG = 'Auth Tag verification failed: The JWT signature is invalid or has been altered';
    case INVALID_KID_FORMAT = 'Invalid "kid" format. Allowed characters are letters, numbers, "-", and "_".';
    case INVALID_KID_LENGTH = 'The "kid" must be between %s and %s characters.';
}
