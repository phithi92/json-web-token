<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Security;

use Phithi92\JsonWebToken\Exceptions\ErrorMessageTrait;

/**
 * Defines standardized error message templates for JWT security operations.
 *
 * Messages may contain sprintf-compatible placeholders (e.g. %s, %1$s)
 * for runtime value injection.
 */
enum SecurityErrorMessagesEnum: string
{
    use ErrorMessageTrait;

    case PASSPHRASE_NOT_FOUND = 'No passphrase found for ID: %1$s';
}
