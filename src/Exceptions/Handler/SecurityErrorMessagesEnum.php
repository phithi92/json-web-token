<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Handler;

use Phithi92\JsonWebToken\Exceptions\ErrorMessageTrait;

/**
 * Enum for JSON-related error messages.
 *
 * Provides standardized messages for encoding and decoding errors, with
 * optional details for more context.
 */
enum HandlerErrorMessagesEnum: string
{
    use ErrorMessageTrait;

    case UNDEFINED_HANDLER = 'Handler "%1$s" does not implement method "%2$s()".';
    case MISSING_HANDLER_CONFIG = 'Missing configuration for handler of type "%1$s".';
    case INVALID_HANDLER_CLASS = 'Handler "%1$s" must implement interface "%2$s".';
    case INVALID_HANDLER_DEFINITION = 'Handler class definition is invalid: received "%1$s".';
    case UNSUPPORTED_HANDLER_METHOD = 'Unsupported handler method for type "%1$s" and operation "%2$s".';
}
