<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Payload;

class InvalidDateTimeException extends PayloadException
{
    public function __construct(string $field)
    {
        parent::__construct(ErrorMessagesEnum::INVALID_DATETIME->getMessage($field));
    }
}
