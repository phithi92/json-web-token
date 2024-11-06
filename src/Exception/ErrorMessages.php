<?php

namespace Phithi92\JsonWebToken\Exception;

use Phithi92\JsonWebToken\Exception\ErrorMessageTrait;

/**
 * Enum for JSON-related error messages.
 *
 * Provides standardized messages for encoding and decoding errors, with
 * optional details for more context.
 */
enum ErrorMessages: string
{
    use ErrorMessageTrait;

    case EMPTY_VALUE = "invalid value. empty value for %s";
}
