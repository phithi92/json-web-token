<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Payload;

use Phithi92\JsonWebToken\Exceptions\ErrorMessageTrait;

/**
 * Enum for JSON-related error messages.
 *
 * Provides standardized messages for encoding and decoding errors, with
 * optional details for more context.
 */
enum PayloadErrorMessagesEnum: string
{
    use ErrorMessageTrait;

    case EXPIRED_PAYLOAD = 'Payload is expired.';
    case FUTURE_TOKEN = 'Payload is not valid yet';
    case NBF_BEFORE_IAT = 'Not before (nbf) must be later than or equal to issued at (iat).';
    case VALUE_NOT_FOUND = 'Payload validation failed. The %s is required in the body but was not found';
    case INVALID_DATETIME = 'Invalid date %s';
    case NO_OVERWRITE = 'Cannot overwrite existing data';
    case INVALID_ISSUER = 'Invalid issuer. got %2$s, expect %1$s.';
    case INVALID_ISSUED_AT = 'Invalid issued at';
    case INVALID_AUDIENCE = 'Audience is not valid: %s';
    case PAYLOAD_EXPIRED = 'Payload is expired';
    case INVALID_IAT = 'Invalid iat. Iat is earlier than exp';
    case INVALID_VALUE_TYPE = 'Invalid value type for key "%1$s". Given: %2$s.';
    case INVALID_KEY_TYPE = 'Invalid key type. Key: "%1$s", Type: %2$s.';
    case EMPTY_VALUE = 'Invalid value. empty value for %s';
}
