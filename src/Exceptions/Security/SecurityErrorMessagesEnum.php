<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Security;

use Phithi92\JsonWebToken\Exceptions\ErrorMessageTrait;

/**
 * Enum for JSON-related error messages.
 *
 * Provides standardized messages for encoding and decoding errors, with
 * optional details for more context.
 */
enum SecurityErrorMessagesEnum: string
{
    use ErrorMessageTrait;

    case PASSPHRASE_NOT_FOUND = 'No passphrase found for ID: %1$s';
}
