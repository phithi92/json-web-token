<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

class MissingKidException extends TokenException
{
    public function __construct()
    {
        parent::__construct('KID_NOT_SET');
    }
}
