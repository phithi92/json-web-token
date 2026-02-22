<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

final class InvalidJwtIdException extends TokenException
{
    public function __construct()
    {
        parent::__construct('INVALID_JTI');
    }
}
