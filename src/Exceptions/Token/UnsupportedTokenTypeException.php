<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

class UnsupportedTokenTypeException extends TokenException
{
    public function __construct(string $type)
    {
        parent::__construct('UNSUPPORTED_TOKEN_TYPE', $type);
    }
}
