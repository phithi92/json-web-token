<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto\Pipeline;

use Phithi92\JsonWebToken\Crypto\Pipeline\AlgorithmInvocation;

class AlgorithmMethodNotFoundException extends AlgorithmInvocationException
{
    public function __construct(AlgorithmInvocation $invocation, string $method)
    {
        parent::__construct('UNDEFINED_HANDLER', $invocation->target->name, $method);
    }
}
