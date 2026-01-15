<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Payload;

class InvalidDateTimeFloatException extends PayloadException
{
    public function __construct(string $field)
    {
        parent::__construct('INVALID_DATETIME_FLOAT', $field);
    }
}
