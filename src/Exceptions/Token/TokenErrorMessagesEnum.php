<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

use Phithi92\JsonWebToken\Exceptions\ErrorMessageTrait;

/**
 * Defines standardized error message templates for token-related operations.
 *
 * Messages may contain sprintf-compatible placeholders (e.g. %s, %1$s)
 * for runtime value injection.
 */
enum TokenErrorMessagesEnum: string
{
    use ErrorMessageTrait;

    case UNSUPPORTED_TOKEN_TYPE = 'Unsupported token type: "%s".';
    case MISSING_HEADER_ALGORITHM = 'JWT header is missing the required "alg" (algorithm) field.';
    case INVALID_SIGNATURE = 'Signature verification failed: %s.';
    case INVALID_FORMAT = 'Invalid JWT format: %s.';
    case INVALID_TOKEN = 'Invalid token: %s.';
    case INVALID_AUTH_TAG = 'Authentication tag mismatch. The ciphertext may be corrupted ' .
        'or has been altered.';
    case INVALID_KID_LENGTH = 'Invalid "kid" length: expected between %s and %s characters.';
    case INVALID_CEK_LENGTH = 'Invalid CEK length: expected %s bits, got %s bits.';
    case INVALID_JTI = 'Invalid "jti" claim: the token identifier is explicitly rejected.';
    case MISSING_JTI = 'Missing required "jti" claim.';
    case JTI_REQUIRES_EXP = 'Cannot manage JWT ID (jti) without expiration time (exp claim). ' .
        'The exp claim is required to determine the denial period.';
    case INVALID_CONFIG_TOKEN_TYPE = 'Invalid configuration: missing or invalid "token_type".';
    case INVALID_PRIVATE_CLAIM = 'Invalid value for private claim "%s": expected "%s".';
    case MISSING_PRIVATE_CLAIM = 'Missing required private claim "%s".';
    case UNRESOLVABLE_KEY = 'No key or passphrase found for the requested secret (KID: "%s").';
    case MISSING_TOKEN_PART = 'Missing required token part: %s.';
    case SIGNATURE_ALREADY_SET = 'JWT signature has already been set.';
    case INDIVIDUAL_MESSAGE = '%s';
    case MALFORMED_TOKEN = 'Malformed token: %s.';
}
