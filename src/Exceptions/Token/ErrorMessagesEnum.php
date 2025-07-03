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

    case INVALID_SIGNATURE          = 'Signature verification failed: %1$s';
    case INVALID_FORMAT             = 'Invalid JWT format: expected three base64url-encoded segments separated by dots.';
    case INVALID_TOKEN              = 'Invalid token: the JWT failed one or more validation steps.';
    case INVALID_AUTH_TAG           = 'Authentication tag mismatch: the ciphertext may have been altered or is corrupted.';
    case INVALID_KID_FORMAT         = 'Invalid "kid" format: only alphanumeric characters, hyphens ("-"), and underscores ("_") are allowed.';
    case INVALID_KID_LENGTH         = 'Invalid "kid" length: must be between %s and %s characters.';
    case INVALID_CEK_LENGTH         = 'Invalid CEK length: expected %2$s bits, but got %1$s bits.';
    case INVALID_JTI                = 'Invalid "jti" claim: the token identifier is not recognized or is explicitly rejected.';
    case COMPUTATION_FAILED         = 'Signature computation failed: %1$s';
    case INVALID_CONFIG_TOKEN_TYPE  = 'Invalid configuration: missing or invalid "token_type" value.';
    case INVALID_PRIVATE_CLAIM      = 'Invalid value for private claim "%1$s". Expect "%2%s".';
    case MISSING_PRIVATE_CLAIM      = 'Missing required private claim "%1$s".';
}
