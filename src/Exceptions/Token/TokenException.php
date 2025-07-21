<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

use Phithi92\JsonWebToken\Exceptions\Exception;
use Phithi92\JsonWebToken\Utilities\EnumUtils;

abstract class TokenException extends Exception
{
    public function __construct(string $type, mixed ...$details)
    {
        $case = EnumUtils::fromName(TokenErrorMessagesEnum::class, $type);
        parent::__construct($case->getMessage(...$details));
    }
}
