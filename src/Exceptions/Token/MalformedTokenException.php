<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

class MalformedTokenException extends TokenException
{
    public function __construct(string $message)
    {
        parent::__construct('INDIVIDUAL_MESSAGE', $message);
    }
}
