<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

class MissingTokenPart extends TokenException
{
    public function __construct(string $part)
    {
        parent::__construct('MISSING_TOKEN_PART', $part);
    }
}
