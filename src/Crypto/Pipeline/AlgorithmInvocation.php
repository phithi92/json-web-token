<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Pipeline;

final class AlgorithmInvocation
{
    public function __construct(
        public readonly CryptoProcessingStage $target,
        public readonly CryptoOperationDirection $operation,
        public readonly int $priority = 100, // default priority
    ) {
    }
}
