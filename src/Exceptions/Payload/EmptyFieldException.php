<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Payload;

class EmptyFieldException extends PayloadException
{
    public function __construct(string|int $name)
    {
        parent::__construct('EMPTY_VALUE', $name);
    }
}
