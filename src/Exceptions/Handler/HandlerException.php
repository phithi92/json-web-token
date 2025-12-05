<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Handler;

use Exception;
use Phithi92\JsonWebToken\Utilities\EnumUtils;

/**
 * Class HandlerException.
 *
 * Base exception for security-related errors in the phithi92/json-web-token package.
 */
abstract class HandlerException extends Exception
{
    public function __construct(string $type, mixed ...$details)
    {
        $case = EnumUtils::fromName(HandlerErrorMessagesEnum::class, $type);
        parent::__construct($case->getMessage(...$details));
    }
}
