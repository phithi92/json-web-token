<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

class InvalidTokenException extends TokenException
{
    public function __construct(string $message)
    {
        parent::__construct('INVALID_TOKEN', $message);
    }
}
