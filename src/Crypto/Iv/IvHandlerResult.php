<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Iv;

use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoStageResultInterface;

final class IvHandlerResult implements CryptoStageResultInterface
{
    public function __construct(
        private readonly string $initializationVector,
    ) {
    }

    public function getInitializationVector(): string
    {
        return $this->initializationVector;
    }
}
