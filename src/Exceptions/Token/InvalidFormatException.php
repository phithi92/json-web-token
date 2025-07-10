<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

class InvalidFormatException extends TokenException
{
    public function __construct(string $message)
    {
        parent::__construct(ErrorMessagesEnum::INVALID_FORMAT->getMessage($message));
    }
}
