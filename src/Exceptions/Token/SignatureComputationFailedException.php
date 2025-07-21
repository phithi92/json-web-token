<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

class SignatureComputationFailedException extends TokenException
{
    public function __construct(string $opensslError)
    {
        parent::__construct('COMPUTATION_FAILED', $opensslError);
    }
}
