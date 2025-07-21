<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Payload;

class ValueNotFoundException extends PayloadException
{
    public function __construct(string $field)
    {
        parent::__construct('VALUE_NOT_FOUND', $field);
    }
}
