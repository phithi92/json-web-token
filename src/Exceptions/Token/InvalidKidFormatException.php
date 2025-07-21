<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

class InvalidKidFormatException extends TokenException
{
    public function __construct()
    {
        parent::__construct('INVALID_KID_FORMAT');
    }
}
