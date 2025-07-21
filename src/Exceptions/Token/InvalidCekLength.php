<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

class InvalidCekLength extends TokenException
{
    public function __construct(int $length, int $expect)
    {
        parent::__construct('INVALID_CEK_LENGTH', $length, $expect);
    }
}
