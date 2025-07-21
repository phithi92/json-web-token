<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

class UnresolvableKeyException extends TokenException
{
    public function __construct(string $kid)
    {
        parent::__construct('UNRESOLVABLE_KEY', $kid);
    }
}
