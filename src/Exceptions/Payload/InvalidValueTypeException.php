<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Payload;

class InvalidValueTypeException extends PayloadException
{
    public function __construct(string $key = '', string $type = '')
    {
        parent::__construct('INVALID_VALUE_TYPE', $key, $type);
    }
}
