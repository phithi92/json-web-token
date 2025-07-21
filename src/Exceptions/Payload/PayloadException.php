<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Payload;

use Exception;
use Phithi92\JsonWebToken\Utilities\EnumUtils;

/**
 * Class PayloadException
 *
 * Base exception for payload-related errors in the phithi92/json-web-token package.
 */
abstract class PayloadException extends Exception
{
    public function __construct(string $type, mixed ...$details)
    {
        $case = EnumUtils::fromName(PayloadErrorMessagesEnum::class, $type);
        parent::__construct($case->getMessage(...$details));
    }
}
