<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto\Pipeline;

class InvalidAlgorithmImplementationException extends AlgorithmInvocationException
{
    public function __construct(string $type)
    {
        parent::__construct('INVALID_HANDLER_DEFINITION', $type);
    }
}
