<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Json;

use Exception;
use Phithi92\JsonWebToken\Support\EnumUtils;

/**
 * Base exception class for JSON-related errors.
 */
abstract class JsonException extends Exception
{
    public function __construct(string $type, mixed ...$details)
    {
        $case = EnumUtils::fromName(JsonErrorMessagesEnum::class, $type);
        parent::__construct($case->getMessage(...$details));
    }
}
