<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto\Pipeline;

class MissingAlgorithmConfigurationException extends AlgorithmInvocationException
{
    public function __construct(string $method)
    {
        parent::__construct('MISSING_HANDLER_CONFIG', $method);
    }
}
