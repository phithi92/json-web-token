<?php

namespace Phithi92\JsonWebToken\Exceptions\Payload;

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

    case FUTURE_TOKEN = 'Payload is not valid yet';
    case NBF_BEFORE_IAT = "Not before (nbf) must be later than or equal to issued at (iat).";
    case VALUE_NOT_FOUND = 'Payload validation failed. The %s is required in the body but was not found';
    case INVALID_DATETIME = "Invalid date %s";
    case NO_OVERWRITE = 'Cannot overwrite existing data';
    case INVALID_ISSUER = 'Invalid issuer';
    case INVALID_ISSUED_AT = 'Invalid issued at';
    case INVALID_AUDIENCE = 'Audience is not valid: %s';
    case PAYLOAD_EXPIRED = "Payload is expired";
    case INVALID_IAT = "invalid iat. Iat is earlier than exp";
    case INVALID_VALUE_TYPE = 'Invalid value type.';
    case EMPTY_VALUE = "invalid value. empty value for %s";
}
