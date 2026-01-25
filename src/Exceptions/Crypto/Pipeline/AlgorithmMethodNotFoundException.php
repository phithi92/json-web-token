<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto\Pipeline;

class AlgorithmMethodNotFoundException extends AlgorithmInvocationException
{
    public function __construct(string $class, string $method)
    {
        parent::__construct('INVALID_IAT', $class, $method);
    }
}
