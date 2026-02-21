<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto\Pipeline;

use Phithi92\JsonWebToken\Crypto\Pipeline\AlgorithmInvocation;

class AlgorithmMethodNotFoundException extends AlgorithmInvocationException
{
    public function __construct(AlgorithmInvocation $invokation)
    {
        parent::__construct('UNDEFINED_HANDLER', $invokation->target->name, $invokation->operation->name);
    }
}
