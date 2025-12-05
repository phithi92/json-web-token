<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Security;

use Exception;
use Phithi92\JsonWebToken\Utilities\EnumUtils;

/**
 * Class SecurityException.
 *
 * Base exception for security-related errors in the phithi92/json-web-token package.
 */
abstract class SecurityException extends Exception
{
    public function __construct(string $type, mixed ...$details)
    {
        $case = EnumUtils::fromName(SecurityErrorMessagesEnum::class, $type);
        parent::__construct($case->getMessage(...$details));
    }
}
