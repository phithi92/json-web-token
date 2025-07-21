<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

class InvalidAuthTagException extends TokenException
{
    public function __construct()
    {
        parent::__construct('INVALID_AUTH_TAG');
    }
}
