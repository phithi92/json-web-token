<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

class InvalidKidLengthException extends TokenException
{
    public function __construct(int $length, int $expect)
    {
        parent::__construct('INVALID_KID_LENGTH', $length, $expect);
    }
}
