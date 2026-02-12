<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto\Pipeline;

use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoOperationDirection;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoProcessingStage;

class AlgorithmMethodNotFoundException extends AlgorithmInvocationException
{
    public function __construct(CryptoProcessingStage $target, CryptoOperationDirection $operation)
    {
        parent::__construct('UNDEFINED_HANDLER', $target->name, $operation->name);
    }
}
