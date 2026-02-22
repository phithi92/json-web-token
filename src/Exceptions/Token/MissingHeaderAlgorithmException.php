<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

class MissingHeaderAlgorithmException extends TokenException
{
    public function __construct(string $message)
    {
        parent::__construct('MISSING_HEADER_ALGORITHM', $message);
    }
}
