<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

final class MissingJwtIdException extends TokenException
{
    public function __construct()
    {
        parent::__construct('MISSING_JTI');
    }
}
